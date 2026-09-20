from __future__ import annotations

from datetime import datetime
import hashlib

from pydantic import Field

from core.analysis.schemas import AIAnalysisV1, AnalysisPacketV1, ModelCallReceiptV1
from core.inventory.models import ReportSnapshotV1, StrictModel


class InventoryRow(StrictModel):
    object_id: str
    object_type: str
    name: str
    location: str
    logical_size_bytes: int = Field(ge=0)
    allocated_size_bytes: int | None = Field(default=None, ge=0)
    reclaimable_estimate_bytes: int | None = Field(default=None, ge=0)
    created_value: datetime | None
    created_source: str
    modified_value: datetime | None
    activity_value: datetime | None
    activity_confidence: str
    time_limitation: str
    rule_hint: str
    ai_observation_ids: str
    user_decision: str = ""
    user_note: str = ""


class PriorityRow(StrictModel):
    priority: str
    object_id: str
    name: str
    logical_size_bytes: int = Field(ge=0)
    reason: str
    uniqueness_risk: str
    rebuild_difficulty: str
    evidence_confidence: str
    inventory_row: int = Field(ge=2)


class DuplicateInstallerRow(StrictModel):
    kind: str
    group_id: str
    object_id: str
    name: str
    location: str
    logical_size_bytes: int = Field(ge=0)
    version_hint: str
    basis: str
    verification_status: str
    next_step: str


class ReportViewModel(StrictModel):
    report_id: str
    artifact_id: str
    snapshot_id: str
    packet_id: str
    analysis_id: str
    generated_at: str
    artifact_privacy_mode: str
    provider: str
    model: str
    analysis_status: str
    analysis_execution_mode: str
    packet_sha256: str
    prompt_version: str
    analysis_schema_version: str
    consent_receipt_id: str
    consent_status: str
    provider_calls: int = Field(ge=0)
    network_calls: int = Field(ge=0)
    input_tokens: int = Field(ge=0)
    cached_input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    estimated_cost: float = Field(ge=0)
    cost_basis: str
    latency_ms: int = Field(ge=0)
    analysis_error_code: str
    analysis_fallback: bool
    analysis_budget: str
    platform: str
    profile: str
    total_logical_size_bytes: int = Field(ge=0)
    total_allocated_size_bytes: int | None = Field(default=None, ge=0)
    total_reclaimable_estimate_bytes: int | None = Field(default=None, ge=0)
    coverage_text: str
    permission_gap_text: str
    limitations: list[str]
    inventory_rows: list[InventoryRow]
    priority_rows: list[PriorityRow]
    duplicate_installer_rows: list[DuplicateInstallerRow]


def build_report_view_model(
    snapshot: ReportSnapshotV1,
    packet: AnalysisPacketV1,
    analysis: AIAnalysisV1,
    receipt: ModelCallReceiptV1 | None = None,
) -> ReportViewModel:
    packet_by_object = {item.object_id: item for item in packet.top_objects}
    findings_by_object: dict[str, list[str]] = {}
    finding_text_by_object: dict[str, list[str]] = {}
    for finding in analysis.findings:
        for object_id in finding.object_ids:
            findings_by_object.setdefault(object_id, []).append(finding.finding_id)
            finding_text_by_object.setdefault(object_id, []).append(finding.observation)
    possible_duplicate = {
        evidence.object_id: evidence
        for evidence in snapshot.evidence
        if evidence.evidence_type == "possible_duplicate"
    }
    lineage_digest = hashlib.sha256(
        (
            f"{snapshot.snapshot_sha256}\0{packet.packet_sha256}"
            f"\0{analysis.analysis_id}\0{analysis.provider}"
        ).encode("utf-8")
    ).hexdigest()
    report_id = f"report_{lineage_digest[:24]}"
    artifact_id = f"artifact_{lineage_digest[24:48]}"
    inventory_rows: list[InventoryRow] = []
    object_row_numbers: dict[str, int] = {}
    ordered_objects = sorted(
        snapshot.objects,
        key=lambda item: (-item.logical_size_bytes, item.object_id),
    )
    for row_number, item in enumerate(ordered_objects, start=2):
        packet_item = packet_by_object.get(item.object_id)
        display_name = packet_item.display_name if packet_item else item.object_id
        location = packet_item.location if packet_item and packet_item.location else "本地标识已最小化"
        object_row_numbers[item.object_id] = row_number
        inventory_rows.append(
            InventoryRow(
                object_id=item.object_id,
                object_type=item.object_type,
                name=display_name,
                location=location,
                logical_size_bytes=item.logical_size_bytes,
                allocated_size_bytes=item.allocated_size_bytes,
                reclaimable_estimate_bytes=item.reclaimable_estimate_bytes,
                created_value=item.created.value,
                created_source=item.created.source,
                modified_value=item.modified.value,
                activity_value=item.accessed.value,
                activity_confidence=item.accessed.confidence,
                time_limitation=item.accessed.limitation or "",
                rule_hint="；".join(hint.message for hint in item.rule_hints),
                ai_observation_ids="；".join(findings_by_object.get(item.object_id, [])),
            )
        )
    priority_rows: list[PriorityRow] = []
    for item in ordered_objects:
        findings = finding_text_by_object.get(item.object_id, [])
        if not item.rule_hints and not findings:
            continue
        priority = item.rule_hints[0].priority if item.rule_hints else "留意即可"
        packet_item = packet_by_object.get(item.object_id)
        priority_rows.append(
            PriorityRow(
                priority=priority,
                object_id=item.object_id,
                name=packet_item.display_name if packet_item else item.object_id,
                logical_size_bytes=item.logical_size_bytes,
                reason="；".join(
                    [*(hint.message for hint in item.rule_hints), *findings]
                ),
                uniqueness_risk="未核验",
                rebuild_difficulty="需用户判断",
                evidence_confidence="中" if item.rule_hints else "低",
                inventory_row=object_row_numbers[item.object_id],
            )
        )
    duplicate_rows: list[DuplicateInstallerRow] = []
    for item in ordered_objects:
        duplicate = possible_duplicate.get(item.object_id)
        if duplicate is None and item.object_type not in {"installer", "archive"}:
            continue
        packet_item = packet_by_object.get(item.object_id)
        kind = "可能重复" if duplicate is not None else "安装包/安装介质"
        group_id = (
            "possible_" + duplicate.evidence_id[-12:]
            if duplicate is not None
            else "installer_" + item.object_id[-12:]
        )
        duplicate_rows.append(
            DuplicateInstallerRow(
                kind=kind,
                group_id=group_id,
                object_id=item.object_id,
                name=packet_item.display_name if packet_item else item.object_id,
                location=(
                    packet_item.location
                    if packet_item and packet_item.location
                    else "本地标识已最小化"
                ),
                logical_size_bytes=item.logical_size_bytes,
                version_hint="未读取内容",
                basis=duplicate.statement if duplicate else "扩展名与目录规则",
                verification_status="尚未核验",
                next_step="人工查看；如需确认重复，进入后续 dedup_confirm。",
            )
        )
    coverage = snapshot.coverage
    return ReportViewModel(
        report_id=report_id,
        artifact_id=artifact_id,
        snapshot_id=snapshot.snapshot_id,
        packet_id=packet.packet_id,
        analysis_id=analysis.analysis_id,
        generated_at=snapshot.generated_at.isoformat(),
        artifact_privacy_mode=packet.artifact_privacy_mode,
        provider=analysis.provider,
        model=analysis.model,
        analysis_status=analysis.status,
        analysis_execution_mode=packet.analysis_execution_mode,
        packet_sha256=packet.packet_sha256,
        prompt_version=receipt.prompt_version if receipt is not None else "",
        analysis_schema_version=(
            receipt.schema_version if receipt is not None else ""
        ),
        consent_receipt_id=(
            receipt.consent_receipt_id
            if receipt is not None and receipt.consent_receipt_id is not None
            else ""
        ),
        consent_status=receipt.consent_status if receipt is not None else "not_required",
        provider_calls=receipt.provider_calls if receipt is not None else 0,
        network_calls=receipt.network_calls if receipt is not None else 0,
        input_tokens=receipt.input_tokens if receipt is not None else 0,
        cached_input_tokens=(
            receipt.cached_input_tokens if receipt is not None else 0
        ),
        output_tokens=receipt.output_tokens if receipt is not None else 0,
        estimated_cost=receipt.estimated_cost if receipt is not None else 0,
        cost_basis=(
            receipt.cost_basis
            if receipt is not None and receipt.cost_basis is not None
            else "not_applicable"
        ),
        latency_ms=receipt.latency_ms if receipt is not None else 0,
        analysis_error_code=(
            receipt.error_code
            if receipt is not None and receipt.error_code is not None
            else ""
        ),
        analysis_fallback=receipt.fallback if receipt is not None else False,
        analysis_budget=(
            receipt.budget.model_dump_json()
            if receipt is not None and receipt.budget is not None
            else ""
        ),
        platform=snapshot.platform,
        profile=snapshot.profile,
        total_logical_size_bytes=snapshot.canonical_tree_logical_size_bytes,
        total_allocated_size_bytes=snapshot.canonical_tree_allocated_size_bytes,
        total_reclaimable_estimate_bytes=snapshot.reclaimable_estimate_bytes,
        coverage_text=(
            f"请求 {coverage.requested_entries} 项；采集 {coverage.collected_entries} 项；"
            f"跳过 {coverage.skipped_entries} 项。"
        ),
        permission_gap_text=(
            "；".join(coverage.permission_gaps) if coverage.permission_gaps else "无"
        ),
        limitations=snapshot.limitations,
        inventory_rows=inventory_rows,
        priority_rows=priority_rows,
        duplicate_installer_rows=duplicate_rows,
    )
