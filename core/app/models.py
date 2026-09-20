from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from core.analysis.privacy import PrivacyLintResult
from core.analysis.schemas import (
    AIAnalysisV1,
    AnalysisBudgetV1,
    AnalysisConsentReceiptV1,
    AnalysisConsentV1,
    AnalysisOfferV1,
    AnalysisPacketV1,
    ModelCallReceiptV1,
)
from core.collectors.checkpoint import CollectorCheckpoint
from core.inventory.models import CoverageV1, ReportSnapshotV1
from core.reports.models import ReportManifestV1


AssetCategory = Literal["photo", "video", "archive", "installer", "document", "pdf", "audio", "other"]
SourceHint = Literal[
    "wechat", "suspected_wechat", "downloads", "desktop", "documents",
    "pictures", "screenshots", "manual_folder", "unknown",
]
AssetStatus = Literal["active", "quarantined", "missing", "ignored"]
ScanStatus = Literal["pending", "running", "completed", "cancelled", "failed", "partial"]
RiskLevel = Literal["low", "medium", "high"]
SuggestionCategory = Literal[
    "safe_to_process", "archive_suggested", "needs_confirmation",
    "sensitive_protected", "likely_unique_original",
]
ProposedAction = Literal["keep", "review", "protect", "quarantine", "archive_suggested"]
OperationAction = Literal["quarantine", "mark_ignored"]
OperationStatus = Literal["succeeded", "partial", "failed", "undone", "undo_partial"]
QuarantineStatus = Literal["quarantined", "restored", "restore_failed", "missing"]


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ErrorResponse(ContractModel):
    code: str
    message: str
    details: dict[str, Any] | None = None
    request_id: str | None = None


class Capabilities(ContractModel):
    real_upload_enabled: Literal[False] = False
    mock_provider_enabled: bool = True
    file_upload_enabled: Literal[False] = False
    cloud_metadata_analysis_available: Literal[False] = False
    cloud_metadata_analysis_enabled: Literal[False] = False
    controlled_synthetic_consent_available: Literal[True] = True


class HealthResponse(ContractModel):
    status: Literal["ok", "degraded"]
    version: str
    db_status: Literal["ok", "unavailable", "migration_required"]
    capabilities: Capabilities
    current_time: datetime


class ScanOptions(ContractModel):
    include_hidden: bool = False
    follow_symlinks: Literal[False] = False
    compute_hash: bool = True
    source_hint_override: SourceHint | None = None


class ScanRequest(ContractModel):
    paths: list[str] = Field(min_length=1)
    options: ScanOptions = Field(default_factory=ScanOptions)


class ErrorSummaryItem(ContractModel):
    code: str
    count: int = Field(ge=0)


class ScanSession(ContractModel):
    id: str
    status: ScanStatus
    requested_paths: list[str]
    started_at: datetime
    finished_at: datetime | None = None
    current_path: str | None = None
    files_seen: int = Field(ge=0)
    files_indexed: int = Field(ge=0)
    files_skipped: int = Field(ge=0)
    bytes_seen: int = Field(ge=0)
    error_summary: list[ErrorSummaryItem] = Field(default_factory=list)


class ScanEvent(ContractModel):
    event_id: str
    scan_session_id: str
    type: Literal["started", "progress", "skipped", "completed", "cancelled", "failed"]
    occurred_at: datetime
    current_path: str | None = None
    files_seen: int = Field(default=0, ge=0)
    files_indexed: int = Field(default=0, ge=0)
    files_skipped: int = Field(default=0, ge=0)
    bytes_seen: int = Field(default=0, ge=0)
    message: str | None = None
    error: ErrorResponse | None = None


class Asset(ContractModel):
    id: str
    abs_path: str
    path_hash: str | None = None
    file_hash: str | None = None
    partial_hash: str | None = None
    hash_status: Literal["not_started", "partial", "full", "failed"] = "not_started"
    size_bytes: int = Field(ge=0)
    ext: str
    mime: str | None = None
    category: AssetCategory
    source_hint: SourceHint
    created_at: datetime | None = None
    modified_at: datetime | None = None
    accessed_at: datetime | None = None
    status: AssetStatus
    scan_session_id: str
    risk_flags: list[str] = Field(default_factory=list)


class AssetMetadata(ContractModel):
    asset_id: str
    key: str
    value: str
    raw_json: dict[str, Any] | None = None


class PageInfo(ContractModel):
    page: int = Field(ge=1)
    page_size: int = Field(ge=1)
    total: int = Field(ge=0)


class AssetList(ContractModel):
    items: list[Asset]
    page: PageInfo


class AssetDetail(ContractModel):
    asset: Asset
    metadata: list[AssetMetadata]


class OverviewBucket(ContractModel):
    key: str
    file_count: int = Field(ge=0)
    size_bytes: int = Field(ge=0)


class RiskSummaryBucket(ContractModel):
    risk_level: RiskLevel
    file_count: int = Field(ge=0)
    size_bytes: int = Field(ge=0)


class FileIntelOverview(ContractModel):
    scan_session_id: str
    total_files: int = Field(ge=0)
    total_size_bytes: int = Field(ge=0)
    by_category: list[OverviewBucket]
    by_source: list[OverviewBucket]
    by_directory: list[OverviewBucket] = Field(default_factory=list)
    top_large_files: list[Asset]
    risk_summary: list[RiskSummaryBucket]
    generated_at: datetime


class DuplicateMember(ContractModel):
    asset_id: str
    role: Literal["keep_recommended", "duplicate_candidate", "protected"]
    similarity: float = Field(ge=0, le=1)
    reason: str | None = None
    risk_level: RiskLevel | None = None


class DuplicateGroup(ContractModel):
    id: str
    kind: Literal["exact"] = "exact"
    file_hash: str | None = None
    member_count: int = Field(ge=2)
    total_size_bytes: int = Field(ge=0)
    reclaimable_size_bytes: int = Field(ge=0)
    keep_asset_id: str
    reason: str
    members: list[DuplicateMember]


class DuplicateGroupList(ContractModel):
    items: list[DuplicateGroup]
    page: PageInfo


class EvidenceItem(ContractModel):
    type: Literal["path", "size", "time", "duplicate", "source", "category", "risk_keyword", "rule"]
    label: str
    value: str


class SuggestionEvidence(ContractModel):
    items: list[EvidenceItem]


class Suggestion(ContractModel):
    id: str
    asset_id: str | None = None
    dup_group_id: str | None = None
    category: SuggestionCategory
    risk_level: RiskLevel
    proposed_action: ProposedAction
    reason: str
    evidence: SuggestionEvidence
    reversible: bool
    default_selected: bool
    status: Literal["active", "ignored", "accepted"]
    created_at: datetime | None = None


class SuggestionList(ContractModel):
    items: list[Suggestion]
    page: PageInfo


class OperationPreviewRequest(ContractModel):
    action_type: OperationAction
    asset_ids: list[str] | None = None
    suggestion_ids: list[str] | None = None
    target_policy: Literal["app_quarantine", "metadata_only"] = "app_quarantine"

    @model_validator(mode="after")
    def validate_authority_and_target(self) -> "OperationPreviewRequest":
        if not self.asset_ids and not self.suggestion_ids:
            raise ValueError("asset_ids 或 suggestion_ids 至少提供一项")
        if self.action_type == "quarantine" and self.target_policy != "app_quarantine":
            raise ValueError("quarantine 必须使用 app_quarantine")
        if self.action_type == "mark_ignored" and self.target_policy != "metadata_only":
            raise ValueError("mark_ignored 必须使用 metadata_only")
        return self


class OperationSummary(ContractModel):
    file_count: int = Field(ge=0)
    total_size_bytes: int = Field(ge=0)
    target_policy: str | None = None


class OperationPlanItem(ContractModel):
    asset_id: str
    suggestion_id: str | None = None
    display_path: str
    size_bytes: int = Field(ge=0)
    risk_level: RiskLevel
    reversible: bool
    warnings: list[str] = Field(default_factory=list)


class OperationPlan(ContractModel):
    id: str
    action_type: OperationAction
    status: Literal["previewed", "expired", "cancelled", "executed"]
    reversible: Literal[True] = True
    summary: OperationSummary
    risk_summary: list[RiskSummaryBucket]
    items: list[OperationPlanItem]
    warnings: list[str]
    version: str
    created_at: datetime
    expires_at: datetime


class OperationExecuteRequest(ContractModel):
    operation_plan_id: str
    confirm: Literal[True]
    client_seen_plan_version: str
    idempotency_key: str | None = Field(default=None, max_length=128)


class OperationUndoRequest(ContractModel):
    confirm: Literal[True]
    conflict_policy: Literal["fail_on_conflict"] = "fail_on_conflict"


class OperationFileResult(ContractModel):
    asset_id: str
    status: Literal["succeeded", "failed", "skipped"]
    original_path: str | None = None
    quarantine_item_id: str | None = None
    error: ErrorResponse | None = None


class OperationReceipt(ContractModel):
    id: str
    operation_plan_id: str
    action_type: OperationAction
    status: OperationStatus
    reversible: Literal[True] = True
    file_count: int = Field(ge=0)
    total_size_bytes: int = Field(ge=0)
    started_at: datetime
    finished_at: datetime | None = None
    affects_cloud_sync: bool = False
    rule_version: str | None = None
    provider_version: str | None = None
    file_results: list[OperationFileResult]


class OperationReceiptList(ContractModel):
    items: list[OperationReceipt]
    page: PageInfo


class QuarantineItem(ContractModel):
    id: str
    operation_id: str
    asset_id: str
    original_path: str
    quarantine_path: str
    original_mtime: datetime | None = None
    original_size_bytes: int = Field(ge=0)
    file_hash: str
    status: QuarantineStatus
    error_message: str | None = None


class QuarantineItemList(ContractModel):
    items: list[QuarantineItem]
    page: PageInfo


class ProviderInfo(ContractModel):
    name: str
    kind: Literal["rules", "mock"]
    runs_locally: Literal[True] = True
    requires_upload: Literal[False] = False
    enabled: bool
    is_stub: bool
    capabilities: list[str] = Field(default_factory=list)


class ProviderList(ContractModel):
    items: list[ProviderInfo]


class MockAnalyzeRequest(ContractModel):
    scan_session_id: str | None = None
    asset_ids: list[str] = Field(default_factory=list)
    prompt: str | None = Field(default=None, max_length=500)


class MockAnalyzeResponse(ContractModel):
    provider: Literal["mock"] = "mock"
    is_mock: Literal[True] = True
    summary: str
    generated_at: datetime


class InventorySafetyCounters(ContractModel):
    product_content_reads: Literal[0] = 0
    product_file_hashes: Literal[0] = 0
    network_calls: Literal[0] = 0
    file_actions: Literal[0] = 0


class InventoryScanCreateRequest(ContractModel):
    fixture_id: Literal["standard"]
    profile: Literal["inventory_metadata"]
    compute_hash: Literal[False] = False


class InventoryScanResponse(ContractModel):
    scan_id: str
    status: Literal["completed", "partial", "failed"]
    fixture_id: Literal["standard"] = "standard"
    profile: Literal["inventory_metadata"] = "inventory_metadata"
    platform: str
    content_read: Literal[False] = False
    hash_mode: Literal["none"] = "none"
    coverage: CoverageV1
    checkpoint: CollectorCheckpoint
    snapshot_id: str
    safety: InventorySafetyCounters = Field(default_factory=InventorySafetyCounters)


class InventorySnapshotCreateRequest(ContractModel):
    scan_id: str


class InventoryPacketPreviewRequest(ContractModel):
    snapshot_id: str
    artifact_privacy_mode: Literal["local_full", "share_safe"]
    analysis_execution_mode: Literal[
        "none",
        "local_only",
        "cloud_metadata_minimized",
    ]
    top_k: int = Field(default=200, ge=1, le=200)
    budget: AnalysisBudgetV1 | None = None


class InventoryPacketPreviewResponse(ContractModel):
    packet: AnalysisPacketV1
    privacy_lint: PrivacyLintResult | None
    estimated_input_tokens: int = Field(ge=1)
    analysis_offer: AnalysisOfferV1 | None = None


class InventoryAnalysisCreateRequest(ContractModel):
    packet_id: str
    provider: Literal["none", "fake"]
    consent: AnalysisConsentV1 | None = None


class InventoryAnalysisResponse(ContractModel):
    analysis: AIAnalysisV1
    receipt: ModelCallReceiptV1
    consent_receipt: AnalysisConsentReceiptV1 | None = None


class InventoryReportCreateRequest(ContractModel):
    snapshot_id: str
    packet_id: str
    analysis_id: str


class InventoryReportResponse(ContractModel):
    report_id: str
    status: Literal["deterministic_only", "ai_complete", "ai_failed_fallback"]
    manifest: ReportManifestV1
    download_url: str
