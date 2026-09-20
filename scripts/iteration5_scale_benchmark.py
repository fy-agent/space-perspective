from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import resource
import subprocess
import sys
import time
from typing import Any
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.analysis.orchestrator import ProductAnalysisCache, analyze_packet
from core.benchmarks.synthetic_metadata import (
    EXPECTED_ROLLING_CHECKSUMS,
    SCALE_GENERATOR_VERSION,
    SUPPORTED_SCALES,
    ScaleBenchmarkStore,
    build_budgeted_scale_packet,
    build_scale_snapshot,
    collect_synthetic_metadata,
)
from core.inventory.models import canonical_json
from core.reports.validation import (
    build_report_manifest,
    validate_workbook,
    workbook_sha256,
)
from core.reports.view_model import build_report_view_model
from core.reports.workbook import render_workbook


OUTPUT_ROOT = ROOT / "output" / "benchmarks" / "iteration5"
SCRIPT_PATH = Path(__file__).resolve()
TOTAL_WALL_LIMITS = {
    10_000: 30.0,
    100_000: 120.0,
    1_000_000: 600.0,
}
PEAK_RSS_LIMIT_MIB = 2_048.0
CANCEL_LATENCY_LIMIT_SECONDS = 2.0
COLLECTION_PER_ENTRY_RATIO_LIMIT = 3.0
SQLITE_PER_ENTRY_RATIO_LIMIT = 2.0


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


def _peak_rss_mib() -> float:
    raw = float(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    if sys.platform == "darwin":
        return raw / (1024 * 1024)
    return raw / 1024


def _trial_directory(scale: int) -> Path:
    now = datetime.now(timezone.utc)
    run_id = uuid4().hex[:12]
    directory = (
        OUTPUT_ROOT
        / f"{now:%Y-%m-%dT%H-%M-%SZ}-{run_id}-scale-{scale}"
    )
    directory.mkdir(parents=True, exist_ok=False)
    return directory


def _phase_payload(result: Any) -> dict[str, Any]:
    return {
        "status": result.state.status,
        "next_ordinal": result.state.next_ordinal,
        "collected_entries": result.state.collected_entries,
        "rolling_checksum": result.state.rolling_checksum,
        "checkpoint_commits": result.state.checkpoint_commits,
        "wall_time_seconds": result.wall_time_seconds,
        "cpu_time_seconds": result.cpu_time_seconds,
        "cancel_detection_latency_seconds": (
            result.cancel_detection_latency_seconds
        ),
        "batches_committed": result.batches_committed,
        "resume_start_ordinal": result.resume_start_ordinal,
        "peak_rss_mib": _peak_rss_mib(),
    }


def _collect_phase(args: argparse.Namespace) -> int:
    result = collect_synthetic_metadata(
        Path(args.database),
        scale=args.scale,
        batch_size=args.batch_size,
        cancel_after_entries=args.cancel_after,
    )
    print(json.dumps(_phase_payload(result), ensure_ascii=False, sort_keys=True))
    return 0


def _run_child_phase(
    *,
    database: Path,
    scale: int,
    batch_size: int,
    cancel_after: int | None,
) -> dict[str, Any]:
    command = [
        sys.executable,
        str(SCRIPT_PATH),
        "_collect-phase",
        "--database",
        str(database),
        "--scale",
        str(scale),
        "--batch-size",
        str(batch_size),
    ]
    if cancel_after is not None:
        command.extend(["--cancel-after", str(cancel_after)])
    completed = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    return json.loads(completed.stdout)


def _run_benchmark(scale: int, batch_size: int) -> tuple[int, Path]:
    if scale not in SUPPORTED_SCALES:
        raise ValueError(f"scale 必须是 {SUPPORTED_SCALES}")
    if not 1 <= batch_size <= 50_000:
        raise ValueError("batch-size 必须位于 1..50000")
    output = _trial_directory(scale)
    database = output / "benchmark.sqlite3"
    workbook = output / "空间透视规模基准报告.xlsx"
    started_at = datetime.now(timezone.utc)
    total_wall_started = time.perf_counter()
    parent_cpu_started = time.process_time()
    _write_json(
        output / "config.sanitized.json",
        {
            "scale": scale,
            "batch_size": batch_size,
            "generator_version": SCALE_GENERATOR_VERSION,
            "provider": "none",
            "real_scope_enabled": False,
            "network_enabled": False,
            "api_key_probed": False,
            "local_model_probed": False,
        },
    )

    cancel_after = min(50_000, max(1_000, scale // 20))
    cancel_phase = _run_child_phase(
        database=database,
        scale=scale,
        batch_size=batch_size,
        cancel_after=cancel_after,
    )
    if (
        cancel_phase["status"] != "cancelled"
        or cancel_phase["next_ordinal"] != cancel_after
    ):
        raise RuntimeError("cancel phase 未形成冻结 checkpoint")
    resume_phase = _run_child_phase(
        database=database,
        scale=scale,
        batch_size=batch_size,
        cancel_after=None,
    )
    store = ScaleBenchmarkStore(database)
    state = store.load()
    if state.status != "completed" or state.next_ordinal != scale:
        raise RuntimeError("resume phase 未完成目标 scale")

    snapshot_started = time.perf_counter()
    snapshot = build_scale_snapshot(state, generated_at=started_at)
    snapshot_wall = time.perf_counter() - snapshot_started

    packet_started = time.perf_counter()
    packet = build_budgeted_scale_packet(snapshot)
    packet_json = canonical_json(packet)
    packet_bytes = len(packet_json.encode("utf-8"))
    estimated_input_tokens = max(1, packet_bytes // 4)
    packet_wall = time.perf_counter() - packet_started

    report_started = time.perf_counter()
    outcome = analyze_packet(
        packet,
        provider="none",
        cache=ProductAnalysisCache(),
    )
    view = build_report_view_model(
        snapshot,
        packet,
        outcome.analysis,
        outcome.receipt,
    )
    render_workbook(view, workbook)
    validation = validate_workbook(
        workbook,
        view=view,
        snapshot=snapshot,
        packet=packet,
        analysis=outcome.analysis,
    )
    manifest = build_report_manifest(
        path=workbook,
        view=view,
        validation=validation,
    )
    report_wall = time.perf_counter() - report_started

    _write_json(output / "snapshot.json", snapshot)
    _write_json(output / "analysis-packet.share-safe.json", packet)
    _write_json(output / "analysis.json", outcome.analysis)
    _write_json(output / "model-call-receipt.json", outcome.receipt)
    _write_json(output / "report-manifest.json", manifest)

    total_wall = time.perf_counter() - total_wall_started
    total_cpu = (
        time.process_time()
        - parent_cpu_started
        + float(cancel_phase["cpu_time_seconds"])
        + float(resume_phase["cpu_time_seconds"])
    )
    peak_rss_mib = max(
        _peak_rss_mib(),
        float(cancel_phase["peak_rss_mib"]),
        float(resume_phase["peak_rss_mib"]),
    )
    sqlite_bytes = database.stat().st_size
    xlsx_sha = workbook_sha256(workbook)
    absolute_gates = {
        "total_wall_within_limit": total_wall <= TOTAL_WALL_LIMITS[scale],
        "cancel_latency_within_2s": (
            float(cancel_phase["cancel_detection_latency_seconds"])
            <= CANCEL_LATENCY_LIMIT_SECONDS
        ),
        "peak_rss_within_limit": (
            scale != 1_000_000 or peak_rss_mib <= PEAK_RSS_LIMIT_MIB
        ),
        "packet_bytes_within_limit": packet_bytes <= 256_000,
        "estimated_input_tokens_within_limit": estimated_input_tokens <= 12_000,
        "top_k_within_limit": len(packet.top_objects) <= 200,
        "provider_calls_zero": outcome.receipt.provider_calls == 0,
        "network_calls_zero": outcome.receipt.network_calls == 0,
        "workbook_valid": (
            validation["passed"]
            and validation["formula_errors"] == 0
            and validation["zip_integrity"]
            and validation["reopen_validated"]
        ),
        "rolling_checksum_matches_contract": (
            state.rolling_checksum == EXPECTED_ROLLING_CHECKSUMS[scale]
        ),
    }
    benchmark = {
        "schema_version": "1.0",
        "status": "passed" if all(absolute_gates.values()) else "failed",
        "evidence_level": "fixture_e2e",
        "scale": scale,
        "generator_version": state.generator_version,
        "seed": state.seed,
        "started_at": started_at.isoformat(),
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "environment": {
            "platform": sys.platform,
            "platform_release": platform.release(),
            "python": platform.python_version(),
            "cpu_count": os.cpu_count(),
            "native_windows": False,
            "real_scope": False,
        },
        "collection": {
            "wall_time_seconds": (
                float(cancel_phase["wall_time_seconds"])
                + float(resume_phase["wall_time_seconds"])
            ),
            "cpu_time_seconds": (
                float(cancel_phase["cpu_time_seconds"])
                + float(resume_phase["cpu_time_seconds"])
            ),
            "per_entry_wall_seconds": (
                float(cancel_phase["wall_time_seconds"])
                + float(resume_phase["wall_time_seconds"])
            )
            / scale,
            "cancel_phase": cancel_phase,
            "resume_phase": resume_phase,
            "checkpoint_commits": state.checkpoint_commits,
            "rolling_checksum": state.rolling_checksum,
            "collected_entries": state.collected_entries,
            "skipped_entries": state.skipped_entries,
        },
        "pipeline": {
            "snapshot_wall_seconds": snapshot_wall,
            "packet_wall_seconds": packet_wall,
            "report_wall_seconds": report_wall,
            "total_wall_seconds": total_wall,
            "total_cpu_seconds": total_cpu,
            "peak_rss_mib": peak_rss_mib,
            "sqlite_bytes": sqlite_bytes,
            "sqlite_bytes_per_entry": sqlite_bytes / scale,
            "snapshot_objects": len(snapshot.objects),
            "snapshot_evidence": len(snapshot.evidence),
            "packet_bytes": packet_bytes,
            "estimated_input_tokens": estimated_input_tokens,
            "top_objects": len(packet.top_objects),
            "xlsx_bytes": workbook.stat().st_size,
            "xlsx_sha256": xlsx_sha,
            "workbook_validation": validation,
        },
        "product_counters": {
            "product_content_reads": 0,
            "product_file_hashes": 0,
            "network_calls": 0,
            "file_actions": 0,
            "provider_calls": outcome.receipt.provider_calls,
        },
        "absolute_gates": absolute_gates,
        "claims_excluded": [
            "real_scope",
            "real_provider",
            "windows_native",
            "excel_wps_open",
            "production",
        ],
    }
    _write_json(output / "benchmark.json", benchmark)
    receipt = {
        "schema_version": "1.0",
        "status": benchmark["status"],
        "evidence_level": "fixture_e2e",
        "scale": scale,
        "benchmark_path": "benchmark.json",
        "database_reopened_between_cancel_and_resume": True,
        "process_restarted_between_cancel_and_resume": True,
        "rolling_checksum": state.rolling_checksum,
        "xlsx_sha256": xlsx_sha,
        "absolute_gates": absolute_gates,
        "product_counters": benchmark["product_counters"],
    }
    _write_json(output / "benchmark-receipt.json", receipt)
    print(json.dumps(benchmark, ensure_ascii=False, sort_keys=True))
    return (0 if benchmark["status"] == "passed" else 9), output


def _latest_for_scale(scale: int) -> Path:
    if not OUTPUT_ROOT.exists():
        raise FileNotFoundError("没有 iteration 5 benchmark 输出")
    candidates: list[Path] = []
    for directory in OUTPUT_ROOT.glob(f"*-scale-{scale}"):
        benchmark = directory / "benchmark.json"
        receipt = directory / "benchmark-receipt.json"
        if benchmark.is_file() and receipt.is_file():
            candidates.append(directory)
    if not candidates:
        raise FileNotFoundError(f"缺少 scale={scale} benchmark")
    return max(candidates, key=lambda path: path.stat().st_mtime_ns)


def _verify_latest_all() -> tuple[int, dict[str, Any]]:
    benchmarks: dict[int, dict[str, Any]] = {}
    directories: dict[int, Path] = {}
    for scale in SUPPORTED_SCALES:
        directory = _latest_for_scale(scale)
        directories[scale] = directory
        benchmark = json.loads(
            (directory / "benchmark.json").read_text(encoding="utf-8")
        )
        receipt = json.loads(
            (directory / "benchmark-receipt.json").read_text(encoding="utf-8")
        )
        if benchmark["scale"] != scale or receipt["scale"] != scale:
            raise ValueError(f"scale={scale} receipt 绑定错误")
        workbook = directory / "空间透视规模基准报告.xlsx"
        if workbook_sha256(workbook) != benchmark["pipeline"]["xlsx_sha256"]:
            raise ValueError(f"scale={scale} XLSX SHA 不匹配")
        benchmarks[scale] = benchmark

    per_entry_100k = benchmarks[100_000]["collection"]["per_entry_wall_seconds"]
    per_entry_1m = benchmarks[1_000_000]["collection"]["per_entry_wall_seconds"]
    sqlite_100k = benchmarks[100_000]["pipeline"]["sqlite_bytes_per_entry"]
    sqlite_1m = benchmarks[1_000_000]["pipeline"]["sqlite_bytes_per_entry"]
    relative_gates = {
        "collection_per_entry_ratio_within_3x": (
            per_entry_1m / max(per_entry_100k, 1e-12)
            <= COLLECTION_PER_ENTRY_RATIO_LIMIT
        ),
        "sqlite_per_entry_ratio_within_2x": (
            sqlite_1m / max(sqlite_100k, 1e-12)
            <= SQLITE_PER_ENTRY_RATIO_LIMIT
        ),
    }
    absolute_pass = all(
        benchmark["status"] == "passed"
        and all(benchmark["absolute_gates"].values())
        for benchmark in benchmarks.values()
    )
    result = {
        "schema_version": "1.0",
        "status": (
            "passed"
            if absolute_pass and all(relative_gates.values())
            else "failed"
        ),
        "evidence_level": "fixture_e2e",
        "scales": {
            str(scale): {
                "directory": str(directories[scale]),
                "benchmark": benchmarks[scale],
            }
            for scale in SUPPORTED_SCALES
        },
        "relative_gates": relative_gates,
        "product_counters": {
            "product_content_reads": 0,
            "product_file_hashes": 0,
            "network_calls": 0,
            "file_actions": 0,
            "provider_calls": 0,
        },
        "claims_excluded": [
            "real_scope",
            "real_provider",
            "windows_native",
            "excel_wps_open",
            "production",
        ],
    }
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    _write_json(OUTPUT_ROOT / "latest-all-verification.json", result)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return (0 if result["status"] == "passed" else 9), result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="空间透视迭代 5 synthetic metadata 规模基准"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    run = subparsers.add_parser("run")
    run.add_argument("--scale", type=int, required=True, choices=SUPPORTED_SCALES)
    run.add_argument("--batch-size", type=int, default=10_000)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--latest-all", action="store_true", required=True)
    phase = subparsers.add_parser("_collect-phase")
    phase.add_argument("--database", required=True)
    phase.add_argument("--scale", type=int, required=True, choices=SUPPORTED_SCALES)
    phase.add_argument("--batch-size", type=int, required=True)
    phase.add_argument("--cancel-after", type=int)
    return parser


def main() -> int:
    args = _parser().parse_args()
    if args.command == "_collect-phase":
        return _collect_phase(args)
    if args.command == "run":
        code, _ = _run_benchmark(args.scale, args.batch_size)
        return code
    code, _ = _verify_latest_all()
    return code


if __name__ == "__main__":
    raise SystemExit(main())
