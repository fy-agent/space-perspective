from __future__ import annotations

import hashlib
import json
from pathlib import Path
from threading import Lock
from typing import Any

from core.analysis.orchestrator import (
    AI_SCHEMA_VERSION,
    PROMPT_VERSION,
    ProductAnalysisCache,
    analyze_packet,
    estimate_output_tokens,
)
from core.analysis.packet import build_packet
from core.analysis.privacy import lint_share_safe_packet
from core.analysis.providers.fake import FakeProvider
from core.analysis.schemas import (
    AnalysisConsentReceiptV1,
    AnalysisOfferV1,
    default_analysis_budget,
)
from core.app.config import Settings
from core.app.errors import DomainError
from core.app.models import (
    InventoryAnalysisCreateRequest,
    InventoryAnalysisResponse,
    InventoryPacketPreviewRequest,
    InventoryPacketPreviewResponse,
    InventoryReportCreateRequest,
    InventoryReportResponse,
    InventorySafetyCounters,
    InventoryScanCreateRequest,
    InventoryScanResponse,
)
from core.collectors.base import ScopeSpec
from core.collectors.filesystem import FileSystemCollector
from core.db.repository import Repository
from core.inventory.models import CoverageV1, ReportSnapshotV1, canonical_json
from core.inventory.snapshots import build_snapshot
from core.reports.models import ReportManifestV1
from core.reports.validation import (
    build_report_manifest,
    validate_workbook,
    workbook_sha256,
)
from core.reports.view_model import build_report_view_model
from core.reports.workbook import render_workbook


ROOT = Path(__file__).parents[2]
FIXTURE_ROOT = ROOT / "fixtures" / "ai-report"
STANDARD_MANIFEST = FIXTURE_ROOT / "standard" / "manifest.json"
EXPECTED_MEMBERS = [
    "normal",
    "privacy",
    "prompt-injection",
    "edge-cases",
]
REPORT_FILENAME = "空间透视盘点报告.xlsx"
SYNTHETIC_DISCLOSURE_VERSION = "synthetic-disclosure-v1"
SYNTHETIC_COST_BASIS = "synthetic_zero_external_cost"
SYNTHETIC_INCLUDED_FIELDS = [
    "coverage",
    "aggregate_sizes",
    "top_governance_objects",
    "rule_hints",
    "evidence_ids",
]
SYNTHETIC_EXCLUDED_FIELDS = [
    "file_content",
    "absolute_path",
    "username",
    "hostname",
    "file_hash",
    "sqlite",
    "api_key",
    "prompt_text",
]
SYNTHETIC_DISCLOSURE = (
    "本轮仅在本地 fake Provider 演练 consent 门禁；不发送数据、不读取 API key、"
    "不产生外部计费；timeout 仅为本地 fake cooperative deadline，"
    "不证明真实 Provider 的超时能力或数据政策。"
)


class InventoryService:
    """Fixture-only inventory/report application service for iteration 2."""

    def __init__(self, repository: Repository, settings: Settings):
        self.repository = repository
        self.settings = settings
        self.analysis_cache = ProductAnalysisCache()
        self.fake_provider = FakeProvider()
        self.analysis_lock = Lock()
        self.report_lock = Lock()

    @staticmethod
    def _load_manifest() -> dict[str, Any]:
        try:
            manifest = json.loads(STANDARD_MANIFEST.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise DomainError(
                "FIXTURE_MANIFEST_INVALID",
                "受控 fixture manifest 无法读取",
                status_code=500,
            ) from exc
        entries = manifest.get("entries")
        if (
            manifest.get("schema_version") != "1.0"
            or manifest.get("fixture_id") != "standard"
            or manifest.get("members") != EXPECTED_MEMBERS
            or not isinstance(entries, list)
            or not entries
        ):
            raise DomainError(
                "FIXTURE_MANIFEST_INVALID",
                "受控 fixture manifest 不符合冻结合同",
                status_code=500,
            )
        for relative in entries:
            path = Path(relative)
            if (
                path.is_absolute()
                or ".." in path.parts
                or not (FIXTURE_ROOT / path).exists()
            ):
                raise DomainError(
                    "FIXTURE_MANIFEST_INVALID",
                    "受控 fixture manifest 包含无效条目",
                    status_code=500,
                )
        return manifest

    @staticmethod
    def _scan_id(manifest: dict[str, Any]) -> str:
        digest = hashlib.sha256(
            (
                f"{manifest['fixture_id']}\0{manifest['fixture_version']}"
                "\0inventory_metadata"
            ).encode("utf-8")
        ).hexdigest()
        return f"scan_fixture_{digest[:24]}"

    @staticmethod
    def _scan_response(record: dict[str, Any]) -> InventoryScanResponse:
        return InventoryScanResponse(
            scan_id=record["scan_id"],
            status=record["checkpoint"]["status"],
            platform=record["platform"],
            coverage=CoverageV1.model_validate(record["coverage"]),
            checkpoint=record["checkpoint"],
            snapshot_id=record["snapshot_id"],
            safety=InventorySafetyCounters(),
        )

    def create_scan(self, request: InventoryScanCreateRequest) -> InventoryScanResponse:
        if request.compute_hash:
            raise DomainError(
                "PROFILE_OPTION_CONFLICT",
                "inventory_metadata 禁止计算文件 hash",
                status_code=422,
            )
        manifest = self._load_manifest()
        scan_id = self._scan_id(manifest)
        existing = self.repository.get_inventory_run(scan_id)
        if existing is not None:
            return self._scan_response(existing)

        collector = FileSystemCollector()
        collection = collector.collect_all(
            ScopeSpec(
                scope_id=scan_id,
                root=FIXTURE_ROOT,
                allowed_root=FIXTURE_ROOT,
                manifest_entries=tuple(manifest["entries"]),
            ),
            profile="inventory_metadata",
        )
        snapshot = build_snapshot(
            scan_id=scan_id,
            facts=collection.facts,
            coverage=collection.coverage,
        )
        self.repository.save_inventory_run(
            scan_id=scan_id,
            platform=snapshot.platform,
            coverage=snapshot.coverage,
            rules_version=snapshot.rules_version,
            checkpoint=collection.checkpoint.model_dump(mode="json"),
            objects=snapshot.objects,
            evidence=snapshot.evidence,
        )
        self.repository.save_snapshot(snapshot)
        stored = self.repository.get_inventory_run(scan_id)
        if stored is None:
            raise DomainError(
                "INVENTORY_PERSISTENCE_FAILED",
                "盘点结果未能持久化",
                status_code=500,
            )
        return self._scan_response(stored)

    def get_scan(self, scan_id: str) -> InventoryScanResponse:
        record = self.repository.get_inventory_run(scan_id)
        if record is None:
            raise DomainError("INVENTORY_SCAN_NOT_FOUND", "盘点任务不存在", status_code=404)
        return self._scan_response(record)

    def create_snapshot(self, scan_id: str) -> ReportSnapshotV1:
        snapshot = self.repository.get_snapshot_for_scan(scan_id)
        if snapshot is not None:
            return snapshot
        if self.repository.get_inventory_run(scan_id) is None:
            raise DomainError("INVENTORY_SCAN_NOT_FOUND", "盘点任务不存在", status_code=404)
        raise DomainError("SNAPSHOT_NOT_READY", "盘点快照尚未就绪", status_code=409)

    def get_snapshot(self, snapshot_id: str) -> ReportSnapshotV1:
        snapshot = self.repository.get_snapshot(snapshot_id)
        if snapshot is None:
            raise DomainError("SNAPSHOT_NOT_FOUND", "盘点快照不存在", status_code=404)
        return snapshot

    def preview_packet(
        self,
        request: InventoryPacketPreviewRequest,
    ) -> InventoryPacketPreviewResponse:
        snapshot = self.get_snapshot(request.snapshot_id)
        if (
            request.analysis_execution_mode == "cloud_metadata_minimized"
            and request.artifact_privacy_mode != "share_safe"
        ):
            raise DomainError(
                "SYNTHETIC_PRIVACY_MODE_MISMATCH",
                "cloud_metadata_minimized 只允许 share_safe packet",
                status_code=409,
            )
        if (
            request.analysis_execution_mode != "cloud_metadata_minimized"
            and request.budget is not None
        ):
            raise DomainError(
                "SYNTHETIC_BUDGET_MODE_MISMATCH",
                "仅 synthetic consent preset 接受预算覆盖",
                status_code=409,
            )
        packet = build_packet(
            snapshot,
            artifact_privacy_mode=request.artifact_privacy_mode,
            analysis_execution_mode=request.analysis_execution_mode,
            top_k=request.top_k,
        )
        self.repository.save_packet(packet)
        lint = (
            lint_share_safe_packet(packet)
            if request.artifact_privacy_mode == "share_safe"
            else None
        )
        estimated_input_tokens = max(
            1,
            len(canonical_json(packet).encode("utf-8")) // 4,
        )
        analysis_offer = None
        if request.analysis_execution_mode == "cloud_metadata_minimized":
            if lint is None or not lint.passed:
                raise DomainError(
                    "SYNTHETIC_PRIVACY_LINT_FAILED",
                    "share_safe packet 未通过隐私检查",
                    status_code=409,
                )
            budget = request.budget or default_analysis_budget()
            analysis_offer = AnalysisOfferV1(
                snapshot_id=snapshot.snapshot_id,
                snapshot_sha256=snapshot.snapshot_sha256,
                packet_id=packet.packet_id,
                packet_sha256=packet.packet_sha256,
                packet_bytes=lint.packet_bytes,
                estimated_input_tokens=estimated_input_tokens,
                estimated_output_tokens=estimate_output_tokens(packet),
                included_field_categories=SYNTHETIC_INCLUDED_FIELDS,
                excluded_field_categories=SYNTHETIC_EXCLUDED_FIELDS,
                budget=budget,
                disclosure=SYNTHETIC_DISCLOSURE,
            )
        return InventoryPacketPreviewResponse(
            packet=packet,
            privacy_lint=lint,
            estimated_input_tokens=estimated_input_tokens,
            analysis_offer=analysis_offer,
        )

    def create_analysis(
        self,
        request: InventoryAnalysisCreateRequest,
    ) -> InventoryAnalysisResponse:
        packet = self.repository.get_packet(request.packet_id)
        if packet is None:
            raise DomainError("ANALYSIS_PACKET_NOT_FOUND", "分析包不存在", status_code=404)
        if request.provider == "fake" and packet.analysis_execution_mode not in {
            "local_only",
            "cloud_metadata_minimized",
        }:
            raise DomainError(
                "ANALYSIS_MODE_MISMATCH",
                "fake provider 只允许 local_only 分析包",
                status_code=409,
            )
        if request.provider == "none" and packet.analysis_execution_mode != "none":
            raise DomainError(
                "ANALYSIS_MODE_MISMATCH",
                "none provider 只允许 none 分析包",
                status_code=409,
            )
        if packet.analysis_execution_mode != "cloud_metadata_minimized":
            if request.consent is not None:
                raise DomainError(
                    "ANALYSIS_CONSENT_NOT_APPLICABLE",
                    "当前分析模式不接受 synthetic consent",
                    status_code=409,
                )
        elif request.consent is None:
            raise DomainError(
                "ANALYSIS_CONSENT_REQUIRED",
                "synthetic 分析需要逐报告显式 consent",
                status_code=409,
            )

        with self.analysis_lock:
            consent_record = None
            if packet.analysis_execution_mode == "cloud_metadata_minimized":
                consent = request.consent
                if consent is None:
                    raise AssertionError("synthetic consent unexpectedly absent")
                identifier_exists = self.repository.analysis_consent_identifier_exists(
                    consent_receipt_id=consent.consent_receipt_id,
                    client_action_id=consent.client_action_id,
                )
                snapshot = self.get_snapshot(packet.snapshot_id)
                packet_bytes = len(canonical_json(packet).encode("utf-8"))
                bindings_match = (
                    consent.snapshot_id == snapshot.snapshot_id
                    and consent.snapshot_sha256 == snapshot.snapshot_sha256
                    and consent.packet_id == packet.packet_id
                    and consent.packet_sha256 == packet.packet_sha256
                    and consent.packet_bytes == packet_bytes
                    and consent.artifact_privacy_mode
                    == packet.artifact_privacy_mode
                    and consent.analysis_execution_mode
                    == packet.analysis_execution_mode
                    and consent.provider == request.provider
                    and consent.model == self.fake_provider.model_name
                    and consent.prompt_version == PROMPT_VERSION
                    and consent.analysis_schema_version == AI_SCHEMA_VERSION
                    and consent.disclosure_version
                    == SYNTHETIC_DISCLOSURE_VERSION
                    and consent.cost_basis == SYNTHETIC_COST_BASIS
                )
                if not bindings_match:
                    raise DomainError(
                        (
                            "ANALYSIS_CONSENT_REUSED"
                            if identifier_exists
                            else "ANALYSIS_CONSENT_MISMATCH"
                        ),
                        "consent 与当前 snapshot、packet、Provider 或预算披露不一致",
                        status_code=409,
                    )
                if identifier_exists:
                    try:
                        self.repository.consume_analysis_consent(consent)
                    except ValueError as exc:
                        raise DomainError(
                            "ANALYSIS_CONSENT_REUSED",
                            "consent receipt 或 client action 已被不同请求使用",
                            status_code=409,
                        ) from exc
                    replay = self.repository.get_analysis_for_client_action(
                        consent.client_action_id
                    )
                    if replay is not None:
                        replay_analysis, replay_receipt, replay_consent = replay
                        return InventoryAnalysisResponse(
                            analysis=replay_analysis,
                            receipt=replay_receipt,
                            consent_receipt=replay_consent,
                        )
                    raise DomainError(
                        "ANALYSIS_CONSENT_IN_PROGRESS",
                        "该 consent action 已保留但尚未形成可回读结果",
                        status_code=409,
                    )
                try:
                    consent_record = self.repository.consume_analysis_consent(
                        consent
                    )
                except ValueError as exc:
                    raise DomainError(
                        "ANALYSIS_CONSENT_REUSED",
                        "consent receipt 或 client action 已被不同请求使用",
                        status_code=409,
                    ) from exc
                if not consent_record["newly_reserved"]:
                    replay = self.repository.get_analysis_for_client_action(
                        consent.client_action_id
                    )
                    if replay is not None:
                        replay_analysis, replay_receipt, replay_consent = replay
                        return InventoryAnalysisResponse(
                            analysis=replay_analysis,
                            receipt=replay_receipt,
                            consent_receipt=replay_consent,
                        )
                    raise DomainError(
                        "ANALYSIS_CONSENT_IN_PROGRESS",
                        "该 consent action 已保留但尚未形成可回读结果",
                        status_code=409,
                    )
            gateway = self.fake_provider if request.provider == "fake" else None
            if request.provider == "fake":
                stored = self.repository.get_analysis_for_packet_provider(
                    request.packet_id,
                    "fake",
                )
                if stored is not None:
                    stored_analysis, stored_receipt = stored
                    if (
                        stored_analysis.status == "ai_complete"
                        and stored_receipt.status in {"succeeded", "cache_hit"}
                        and stored_receipt.model == self.fake_provider.model_name
                        and stored_receipt.prompt_version == PROMPT_VERSION
                        and stored_receipt.schema_version == AI_SCHEMA_VERSION
                    ):
                        self.analysis_cache.values[stored_receipt.cache_key] = stored_analysis
            outcome = analyze_packet(
                packet,
                provider=request.provider,
                gateway=gateway,
                cache=self.analysis_cache,
                budget=(
                    request.consent.budget
                    if request.consent is not None
                    else None
                ),
                consent=request.consent,
            )
            consent_receipt = None
            if request.consent is not None:
                consent_payload = (
                    self.repository.save_synthetic_analysis_and_finalize_consent(
                        outcome.analysis,
                        outcome.receipt,
                    )
                )
                consent_receipt = AnalysisConsentReceiptV1.model_validate(
                    consent_payload
                )
            else:
                self.repository.save_analysis(outcome.analysis, outcome.receipt)
        return InventoryAnalysisResponse(
            analysis=outcome.analysis,
            receipt=outcome.receipt,
            consent_receipt=consent_receipt,
        )

    def get_analysis(self, analysis_id: str) -> InventoryAnalysisResponse:
        stored = self.repository.get_analysis(analysis_id)
        if stored is None:
            raise DomainError("ANALYSIS_NOT_FOUND", "分析结果不存在", status_code=404)
        analysis, receipt = stored
        consent_receipt = None
        if receipt.consent_receipt_id is not None:
            stored_consent = self.repository.get_analysis_consent(
                receipt.consent_receipt_id
            )
            if stored_consent is not None:
                consent_receipt = AnalysisConsentReceiptV1.model_validate(
                    stored_consent
                )
        return InventoryAnalysisResponse(
            analysis=analysis,
            receipt=receipt,
            consent_receipt=consent_receipt,
        )

    @staticmethod
    def _report_response(manifest: ReportManifestV1) -> InventoryReportResponse:
        return InventoryReportResponse(
            report_id=manifest.report_id,
            status=manifest.analysis_status,
            manifest=manifest,
            download_url=f"/v1/inventory/reports/{manifest.report_id}/download",
        )

    def create_report(
        self,
        request: InventoryReportCreateRequest,
    ) -> InventoryReportResponse:
        snapshot = self.repository.get_snapshot(request.snapshot_id)
        if snapshot is None:
            raise DomainError("SNAPSHOT_NOT_FOUND", "盘点快照不存在", status_code=404)
        packet = self.repository.get_packet(request.packet_id)
        if packet is None:
            raise DomainError("ANALYSIS_PACKET_NOT_FOUND", "分析包不存在", status_code=404)
        stored_analysis = self.repository.get_analysis(request.analysis_id)
        if stored_analysis is None:
            raise DomainError("ANALYSIS_NOT_FOUND", "分析结果不存在", status_code=404)
        analysis, analysis_receipt = stored_analysis
        if packet.snapshot_id != snapshot.snapshot_id or analysis.packet_id != packet.packet_id:
            raise DomainError(
                "REPORT_LINEAGE_MISMATCH",
                "报告输入不属于同一条快照与分析链",
                status_code=409,
            )
        with self.report_lock:
            existing = self.repository.get_report_for_inputs(
                snapshot_id=request.snapshot_id,
                packet_id=request.packet_id,
                analysis_id=request.analysis_id,
            )
            if existing is not None:
                return self._report_response(existing)

            view = build_report_view_model(
                snapshot,
                packet,
                analysis,
                analysis_receipt,
            )
            output_path = (
                self.settings.resolved_inventory_report_path
                / view.report_id
                / REPORT_FILENAME
            )
            render_workbook(view, output_path)
            validation = validate_workbook(
                output_path,
                view=view,
                snapshot=snapshot,
                packet=packet,
                analysis=analysis,
            )
            manifest = build_report_manifest(
                path=output_path,
                view=view,
                validation=validation,
            )
            self.repository.save_report_artifact(manifest)
        return self._report_response(manifest)

    def get_report(self, report_id: str) -> InventoryReportResponse:
        manifest = self.repository.get_report_manifest(report_id)
        if manifest is None:
            raise DomainError("REPORT_NOT_FOUND", "报告不存在", status_code=404)
        return self._report_response(manifest)

    def report_download(self, report_id: str) -> tuple[Path, ReportManifestV1]:
        manifest = self.repository.get_report_manifest(report_id)
        if manifest is None:
            raise DomainError("REPORT_NOT_FOUND", "报告不存在", status_code=404)
        root = self.settings.resolved_inventory_report_path.resolve()
        candidate = root / manifest.report_id / manifest.filename
        path = candidate.resolve()
        if not path.is_relative_to(root):
            raise DomainError(
                "REPORT_ARTIFACT_INVALID",
                "报告制品定位无效",
                status_code=409,
            )
        relative_parts = candidate.relative_to(root).parts
        current = root
        has_symlink = False
        for part in relative_parts:
            current = current / part
            if current.is_symlink():
                has_symlink = True
                break
        if has_symlink:
            raise DomainError(
                "REPORT_ARTIFACT_INVALID",
                "报告制品定位无效",
                status_code=409,
            )
        if not path.is_file():
            raise DomainError(
                "REPORT_ARTIFACT_MISSING",
                "报告制品尚不可下载",
                status_code=409,
            )
        if workbook_sha256(path) != manifest.workbook_sha256:
            raise DomainError(
                "REPORT_ARTIFACT_HASH_MISMATCH",
                "报告制品完整性校验失败",
                status_code=409,
            )
        return path, manifest
