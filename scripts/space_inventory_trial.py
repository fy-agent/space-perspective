from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
from typing import Any
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from core.analysis.orchestrator import ProductAnalysisCache, analyze_packet
from core.analysis.packet import build_packet_pair
from core.analysis.privacy import lint_share_safe_packet, privacy_diff
from core.analysis.providers.fake import FakeProvider
from core.analysis.schemas import AIAnalysisV1, AnalysisPacketV1, ModelCallReceiptV1
from core.collectors.base import ScopeSpec
from core.collectors.filesystem import FileSystemCollector
from core.db.connection import initialize_database
from core.db.repository import Repository
from core.inventory.snapshots import build_snapshot
from core.inventory.models import ReportSnapshotV1, canonical_json
from core.reports.models import ReportManifestV1
from core.reports.validation import (
    build_report_manifest,
    validate_workbook,
)
from core.reports.view_model import build_report_view_model
from core.reports.workbook import render_workbook


FIXTURE_ROOT = ROOT / "fixtures" / "ai-report"
STANDARD_MANIFEST = FIXTURE_ROOT / "standard" / "manifest.json"
TRIALS_ROOT = ROOT / "output" / "trials"
EXPECTED_OUTPUTS = [
    "config.sanitized.json",
    "preflight.json",
    "fixture-manifest.json",
    "inventory.ndjson",
    "coverage.json",
    "checkpoint.json",
    "governance-objects.json",
    "evidence.json",
    "snapshot.json",
    "analysis-packet.local-full.json",
    "analysis-packet.share-safe.json",
    "privacy-diff.json",
    "packet-manifest.json",
    "analysis.json",
    "model-call-receipt.json",
    "空间透视盘点报告.xlsx",
    "report-manifest.json",
    "verification.json",
    "trial-receipt.json",
]


def _write_json(path: Path, value: Any) -> None:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    path.write_text(
        json.dumps(
            value,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            default=lambda item: (
                item.model_dump(mode="json")
                if hasattr(item, "model_dump")
                else item.isoformat()
            ),
        )
        + "\n",
        encoding="utf-8",
    )


def _load_manifest() -> dict[str, Any]:
    manifest = json.loads(STANDARD_MANIFEST.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != "1.0":
        raise ValueError("fixture manifest schema_version 无效")
    if manifest.get("members") != [
        "normal",
        "privacy",
        "prompt-injection",
        "edge-cases",
    ]:
        raise ValueError("standard fixture 成员或顺序无效")
    entries = manifest.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ValueError("standard fixture entries 缺失")
    for relative in entries:
        path = Path(relative)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("fixture manifest entry 越界")
        if not (FIXTURE_ROOT / path).exists():
            raise ValueError(f"fixture entry 不存在：{relative}")
    return manifest


def _fixture_integrity(manifest: dict[str, Any]) -> tuple[list[dict[str, Any]], int]:
    records: list[dict[str, Any]] = []
    hashes = 0
    paths = sorted(
        FIXTURE_ROOT.rglob("*"),
        key=lambda path: path.relative_to(FIXTURE_ROOT).as_posix(),
    )
    for path in paths:
        relative = path.relative_to(FIXTURE_ROOT).as_posix()
        info = path.stat(follow_symlinks=False)
        record = {
            "relative_path": relative,
            "kind": "directory" if path.is_dir() else "file",
            "size": info.st_size,
            "mtime_ns": info.st_mtime_ns,
            "sha256": None,
        }
        if path.is_file():
            digest = hashlib.sha256()
            with path.open("rb") as source:
                while chunk := source.read(1024 * 1024):
                    digest.update(chunk)
            record["sha256"] = digest.hexdigest()
            hashes += 1
        records.append(record)
    return records, hashes


def _preflight_payload() -> dict[str, Any]:
    manifest = _load_manifest()
    return {
        "status": "passed",
        "fixture": manifest["fixture_id"],
        "fixture_version": manifest["fixture_version"],
        "providers_allowed": ["none", "fake"],
        "api_key_probed": False,
        "local_model_probed": False,
        "network_required": False,
        "platform": sys.platform,
        "native_windows": False,
        "windows_status": "NATIVE_WINDOWS_REQUIRED",
        "sqlite_version": sqlite3.sqlite_version,
        "openpyxl_available": True,
        "output_root": str(TRIALS_ROOT),
    }


def _schema_registry() -> tuple[dict[str, dict[str, Any]], Registry]:
    schemas: dict[str, dict[str, Any]] = {}
    registry = Registry()
    for path in sorted((ROOT / "shared" / "schemas").glob("*-v1.schema.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        schemas[path.name] = document
        registry = registry.with_resource(
            document["$id"],
            Resource.from_contents(document),
        )
    return schemas, registry


def _validate_schemas(
    *,
    facts: list[Any],
    snapshot: ReportSnapshotV1,
    packets: tuple[AnalysisPacketV1, AnalysisPacketV1],
    analysis: AIAnalysisV1,
    manifest: ReportManifestV1,
) -> int:
    schemas, registry = _schema_registry()

    def validate(schema_name: str, value: Any) -> None:
        payload = value.model_dump(mode="json") if hasattr(value, "model_dump") else value
        Draft202012Validator(
            schemas[schema_name],
            registry=registry,
            format_checker=Draft202012Validator.FORMAT_CHECKER,
        ).validate(payload)

    for fact in facts:
        validate("scan-fact-v1.schema.json", fact)
    for item in snapshot.objects:
        validate("governance-object-v1.schema.json", item)
    validate("report-snapshot-v1.schema.json", snapshot)
    for packet in packets:
        validate("analysis-packet-v1.schema.json", packet)
    validate("ai-analysis-v1.schema.json", analysis)
    validate("report-manifest-v1.schema.json", manifest)
    return 6


def _trial_directory() -> tuple[str, Path]:
    now = datetime.now(timezone.utc)
    trial_id = uuid4().hex[:12]
    directory = TRIALS_ROOT / f"{now:%Y-%m-%dT%H-%M-%SZ}-{trial_id}"
    directory.mkdir(parents=True, exist_ok=False)
    return trial_id, directory


def run_trial(*, provider: str, privacy: str) -> tuple[int, Path]:
    trial_id, output = _trial_directory()
    started_at = datetime.now(timezone.utc)
    manifest = _load_manifest()
    preflight = _preflight_payload()
    before, before_hashes = _fixture_integrity(manifest)
    _write_json(
        output / "config.sanitized.json",
        {
            "fixture": "standard",
            "profile": "inventory_metadata",
            "provider": provider,
            "privacy": privacy,
            "api_key_present": False,
            "real_scope_enabled": False,
            "network_enabled": False,
        },
    )
    _write_json(output / "preflight.json", preflight)
    _write_json(
        output / "fixture-manifest.json",
        {"manifest": manifest, "integrity_before": before},
    )

    collector = FileSystemCollector()
    collection = collector.collect_all(
        ScopeSpec(
            scope_id=f"scan_fixture_{trial_id}",
            root=FIXTURE_ROOT,
            allowed_root=FIXTURE_ROOT,
            manifest_entries=tuple(manifest["entries"]),
        )
    )
    (output / "inventory.ndjson").write_text(
        "".join(canonical_json(fact) + "\n" for fact in collection.facts),
        encoding="utf-8",
    )
    _write_json(output / "coverage.json", collection.coverage)
    _write_json(output / "checkpoint.json", collection.checkpoint)

    snapshot = build_snapshot(
        scan_id=f"scan_fixture_{trial_id}",
        facts=collection.facts,
        coverage=collection.coverage,
        generated_at=started_at,
    )
    _write_json(output / "governance-objects.json", snapshot.objects)
    _write_json(output / "evidence.json", snapshot.evidence)
    _write_json(output / "snapshot.json", snapshot)

    execution_mode = "none" if provider == "none" else "local_only"
    local_full, share_safe = build_packet_pair(
        snapshot,
        analysis_execution_mode=execution_mode,
    )
    _write_json(output / "analysis-packet.local-full.json", local_full)
    _write_json(output / "analysis-packet.share-safe.json", share_safe)
    privacy_diff_value = privacy_diff(local_full, share_safe)
    _write_json(output / "privacy-diff.json", privacy_diff_value)
    _write_json(
        output / "packet-manifest.json",
        {
            "schema_version": "1.0",
            "snapshot_id": snapshot.snapshot_id,
            "local_full_packet_id": local_full.packet_id,
            "local_full_sha256": local_full.packet_sha256,
            "share_safe_packet_id": share_safe.packet_id,
            "share_safe_sha256": share_safe.packet_sha256,
            "share_safe_lint": lint_share_safe_packet(share_safe).model_dump(mode="json"),
        },
    )
    selected = local_full if privacy == "local_full" else share_safe
    gateway = FakeProvider() if provider == "fake" else None
    outcome = analyze_packet(
        selected,
        provider=provider,
        gateway=gateway,
        cache=ProductAnalysisCache(),
    )
    _write_json(output / "analysis.json", outcome.analysis)
    _write_json(output / "model-call-receipt.json", outcome.receipt)

    view = build_report_view_model(snapshot, selected, outcome.analysis)
    workbook_path = output / "空间透视盘点报告.xlsx"
    render_workbook(view, workbook_path)
    workbook_validation = validate_workbook(
        workbook_path,
        view=view,
        snapshot=snapshot,
        packet=selected,
        analysis=outcome.analysis,
    )
    report_manifest = build_report_manifest(
        path=workbook_path,
        view=view,
        validation=workbook_validation,
    )
    _write_json(output / "report-manifest.json", report_manifest)

    database_path = output / "trial.sqlite3"
    initialize_database(database_path)
    repository = Repository(database_path)
    repository.save_inventory_run(
        scan_id=snapshot.scan_id,
        platform=snapshot.platform,
        coverage=snapshot.coverage,
        rules_version=snapshot.rules_version,
        checkpoint=collection.checkpoint.model_dump(mode="json"),
        objects=snapshot.objects,
        evidence=snapshot.evidence,
    )
    repository.save_snapshot(snapshot)
    repository.save_packet(local_full)
    repository.save_packet(share_safe)
    repository.save_analysis(outcome.analysis, outcome.receipt)
    repository.save_report_artifact(report_manifest)

    schema_count = _validate_schemas(
        facts=list(collection.facts),
        snapshot=snapshot,
        packets=(local_full, share_safe),
        analysis=outcome.analysis,
        manifest=report_manifest,
    )
    after, after_hashes = _fixture_integrity(manifest)
    fixture_unchanged = before == after
    product_counters = collection.counters
    verification = {
        "status": "passed" if fixture_unchanged else "failed",
        "schema_files_validated": schema_count,
        "fixture_unchanged": fixture_unchanged,
        "fixture_allowed_region_changes": 0 if fixture_unchanged else 1,
        "share_safe_privacy_lint": privacy_diff_value["share_safe_lint"],
        "workbook": workbook_validation,
        "database_schema_version": 3,
        "provider_calls": outcome.receipt.provider_calls,
        "network_calls": outcome.receipt.network_calls,
        "product_content_reads": product_counters.product_content_reads,
        "product_file_hashes": product_counters.product_file_hashes,
        "prompt_injection_boundary": (
            "delete" not in canonical_json(outcome.analysis).casefold()
        ),
    }
    _write_json(output / "verification.json", verification)
    finished_at = datetime.now(timezone.utc)
    trial_receipt = {
        "trial_id": trial_id,
        "mode": "fixture",
        "platform": snapshot.platform,
        "profile": "inventory_metadata",
        "scope_fingerprint": "fixture:standard:" + manifest["fixture_version"],
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "steps": [
            "preflight",
            "collect",
            "aggregate",
            "build-packet",
            "analyze",
            "render",
            "verify",
        ],
        "files_seen": collection.coverage.requested_entries,
        "files_failed": collection.coverage.skipped_entries,
        "product_content_reads": product_counters.product_content_reads,
        "product_file_hashes": product_counters.product_file_hashes,
        "fixture_integrity_hashes": before_hashes + after_hashes,
        "provider_calls": outcome.receipt.provider_calls,
        "network_calls": outcome.receipt.network_calls,
        "input_tokens": outcome.receipt.input_tokens,
        "cached_input_tokens": outcome.receipt.cached_input_tokens,
        "output_tokens": outcome.receipt.output_tokens,
        "packet_sha256": selected.packet_sha256,
        "report_sha256": report_manifest.workbook_sha256,
        "privacy_mode": privacy,
        "fixture_unchanged": fixture_unchanged,
        "result": "passed" if fixture_unchanged else "failed",
    }
    _write_json(output / "trial-receipt.json", trial_receipt)
    missing = [name for name in EXPECTED_OUTPUTS if not (output / name).exists()]
    if missing:
        raise RuntimeError(f"缺少 trial 输出：{missing}")
    if not fixture_unchanged:
        return 9, output
    return 0, output


def _latest_trial() -> Path:
    if not TRIALS_ROOT.exists():
        raise FileNotFoundError("没有可验证的 trial")
    candidates = sorted(path for path in TRIALS_ROOT.iterdir() if path.is_dir())
    if not candidates:
        raise FileNotFoundError("没有可验证的 trial")
    return max(candidates, key=lambda path: path.stat().st_mtime_ns)


def verify_trial(directory: Path) -> dict[str, Any]:
    snapshot = ReportSnapshotV1.model_validate_json(
        (directory / "snapshot.json").read_text(encoding="utf-8")
    )
    local_full = AnalysisPacketV1.model_validate_json(
        (directory / "analysis-packet.local-full.json").read_text(encoding="utf-8")
    )
    share_safe = AnalysisPacketV1.model_validate_json(
        (directory / "analysis-packet.share-safe.json").read_text(encoding="utf-8")
    )
    analysis = AIAnalysisV1.model_validate_json(
        (directory / "analysis.json").read_text(encoding="utf-8")
    )
    receipt = ModelCallReceiptV1.model_validate_json(
        (directory / "model-call-receipt.json").read_text(encoding="utf-8")
    )
    manifest = ReportManifestV1.model_validate_json(
        (directory / "report-manifest.json").read_text(encoding="utf-8")
    )
    selected = local_full if manifest.artifact_privacy_mode == "local_full" else share_safe
    view = build_report_view_model(snapshot, selected, analysis)
    workbook_validation = validate_workbook(
        directory / manifest.filename,
        view=view,
        snapshot=snapshot,
        packet=selected,
        analysis=analysis,
    )
    trial_receipt = json.loads(
        (directory / "trial-receipt.json").read_text(encoding="utf-8")
    )
    previous = json.loads(
        (directory / "verification.json").read_text(encoding="utf-8")
    )
    missing = [name for name in EXPECTED_OUTPUTS if not (directory / name).exists()]
    result = {
        **previous,
        "status": "passed",
        "trial_directory": str(directory),
        "required_outputs": len(EXPECTED_OUTPUTS),
        "missing_outputs": missing,
        "workbook": workbook_validation,
        "report_hash_matches": workbook_validation["workbook_sha256"] == manifest.workbook_sha256,
        "product_content_reads": trial_receipt["product_content_reads"],
        "product_file_hashes": trial_receipt["product_file_hashes"],
        "fixture_integrity_hashes": trial_receipt["fixture_integrity_hashes"],
        "provider_calls": receipt.provider_calls,
        "network_calls": receipt.network_calls,
        "fixture_unchanged": trial_receipt["fixture_unchanged"],
    }
    if (
        not result["report_hash_matches"]
        or result["product_content_reads"] != 0
        or result["product_file_hashes"] != 0
        or result["network_calls"] != 0
        or not result["fixture_unchanged"]
        or missing
    ):
        result["status"] = "failed"
    _write_json(directory / "verification.json", result)
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="空间透视 fixture-only AI XLSX 迭代 1 试验器"
    )
    subparsers = parser.add_subparsers(dest="command")

    preflight = subparsers.add_parser("preflight", help="检查 fixture-only runtime")
    preflight.add_argument("--fixture", choices=["standard"], required=True)

    run = subparsers.add_parser("run", help="运行完整 fixture-only 纵切")
    run.add_argument("--fixture", choices=["standard"], required=True)
    run.add_argument("--provider", choices=["none", "fake"], required=True)
    run.add_argument(
        "--privacy",
        choices=["local_full", "share_safe"],
        default="local_full",
    )

    verify = subparsers.add_parser("verify", help="重载并验证最新 trial")
    verify.add_argument("--latest", action="store_true", required=True)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        return 0
    if args.command == "preflight":
        TRIALS_ROOT.mkdir(parents=True, exist_ok=True)
        payload = _preflight_payload()
        _write_json(TRIALS_ROOT / "preflight.json", payload)
        print(json.dumps(payload, ensure_ascii=False))
        return 0
    if args.command == "run":
        code, output = run_trial(provider=args.provider, privacy=args.privacy)
        print(json.dumps({"status": "passed" if code == 0 else "failed", "output": str(output)}, ensure_ascii=False))
        return code
    if args.command == "verify":
        result = verify_trial(_latest_trial())
        print(json.dumps(result, ensure_ascii=False))
        return 0 if result["status"] == "passed" else 9
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
