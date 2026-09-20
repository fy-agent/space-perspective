from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field, model_validator

from core.inventory.models import StrictModel


CONSENT_RECEIPT_ID_PATTERN = (
    r"^consent_receipt_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}$"
)
CLIENT_ACTION_ID_PATTERN = (
    r"^client_action_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}$"
)


class PacketObjectV1(StrictModel):
    object_id: str
    evidence_ids: list[str] = Field(min_length=1)
    object_type: str
    display_name: str
    location: str | None
    name_length: int = Field(ge=0)
    logical_size_bytes: int = Field(ge=0)
    allocated_size_bytes: int | None = Field(default=None, ge=0)
    reclaimable_estimate_bytes: int | None = Field(default=None, ge=0)
    rule_hints: list[str]


class LongTailV1(StrictModel):
    object_count: int = Field(ge=0)
    logical_size_bytes: int = Field(ge=0)


class CoverageSummaryV1(StrictModel):
    requested_entries: int = Field(ge=0)
    collected_entries: int = Field(ge=0)
    skipped_entries: int = Field(ge=0)
    permission_gap_count: int = Field(ge=0)
    cancelled: bool


class AnalysisPacketV1(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    packet_id: str
    packet_sha256: str
    snapshot_id: str
    snapshot_sha256: str
    generated_at: datetime
    artifact_privacy_mode: Literal["local_full", "share_safe"]
    analysis_execution_mode: Literal[
        "none",
        "local_only",
        "cloud_metadata_minimized",
    ]
    profile: Literal["inventory_metadata"] = "inventory_metadata"
    platform: str
    content_read: Literal[False] = False
    hash_mode: Literal["none"] = "none"
    canonical_tree_logical_size_bytes: int = Field(ge=0)
    canonical_tree_allocated_size_bytes: int | None = Field(default=None, ge=0)
    reclaimable_estimate_bytes: int | None = Field(default=None, ge=0)
    coverage_summary: CoverageSummaryV1
    limitations: list[str]
    top_objects: list[PacketObjectV1]
    long_tail: LongTailV1
    truncated: bool


class AIFindingV1(StrictModel):
    finding_id: str
    object_ids: list[str] = Field(min_length=1)
    evidence_ids: list[str] = Field(min_length=1)
    observation: str
    recommendation: Literal["review", "keep", "verify", "archive_consider"]


class AIAnalysisV1(StrictModel):
    schema_version: Literal["1.0"]
    analysis_id: str
    packet_id: str
    status: Literal["deterministic_only", "ai_complete", "ai_failed_fallback"]
    provider: Literal["none", "fake"]
    model: str
    summary: str
    findings: list[AIFindingV1]
    questions: list[str]
    limitations: list[str]


class AnalysisBudgetV1(StrictModel):
    max_provider_calls: Literal[1] = Field(
        description="Primary provider calls only; schema retries are budgeted separately.",
    )
    max_schema_retries: int = Field(
        ge=0,
        le=1,
        description="Additional schema-repair attempts; total attempts are at most two.",
    )
    max_input_tokens: int = Field(ge=1, le=12_000)
    max_output_tokens: int = Field(ge=1, le=2_500)
    max_packet_bytes: int = Field(ge=1, le=256_000)
    timeout_ms: int = Field(
        ge=1,
        le=90_000,
        description=(
            "Cooperative wall-clock deadline enforced by the offline fake provider; "
            "not evidence of a real-provider hard timeout."
        ),
    )
    max_estimated_cost: Literal[0.0]


def default_analysis_budget() -> AnalysisBudgetV1:
    return AnalysisBudgetV1(
        max_provider_calls=1,
        max_schema_retries=1,
        max_input_tokens=12_000,
        max_output_tokens=2_500,
        max_packet_bytes=256_000,
        timeout_ms=90_000,
        max_estimated_cost=0.0,
    )


class AnalysisOfferV1(StrictModel):
    synthetic: Literal[True] = True
    consent_required: Literal[True] = True
    network_calls: Literal[0] = 0
    provider: Literal["fake"] = "fake"
    model: Literal["fixture-analyst-v1"] = "fixture-analyst-v1"
    prompt_version: Literal["report-analysis-v1"] = "report-analysis-v1"
    consent_schema_version: Literal["1.0"] = "1.0"
    analysis_schema_version: Literal["ai-analysis-v1"] = "ai-analysis-v1"
    disclosure_version: Literal[
        "synthetic-disclosure-v1"
    ] = "synthetic-disclosure-v1"
    snapshot_id: str
    snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    packet_id: str
    packet_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    packet_bytes: int = Field(ge=1)
    estimated_input_tokens: int = Field(ge=1)
    estimated_output_tokens: int = Field(ge=1)
    included_field_categories: list[str] = Field(min_length=1)
    excluded_field_categories: list[str] = Field(min_length=1)
    budget: AnalysisBudgetV1
    cost_basis: Literal[
        "synthetic_zero_external_cost"
    ] = "synthetic_zero_external_cost"
    disclosure: str


class AnalysisConsentV1(StrictModel):
    consent_receipt_id: str = Field(pattern=CONSENT_RECEIPT_ID_PATTERN)
    client_action_id: str = Field(pattern=CLIENT_ACTION_ID_PATTERN)
    confirmed: Literal[True]
    snapshot_id: str
    snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    packet_id: str
    packet_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    packet_bytes: int = Field(ge=1)
    artifact_privacy_mode: Literal["share_safe"]
    analysis_execution_mode: Literal["cloud_metadata_minimized"]
    provider: Literal["fake"]
    model: Literal["fixture-analyst-v1"]
    prompt_version: Literal["report-analysis-v1"]
    consent_schema_version: Literal["1.0"]
    analysis_schema_version: Literal["ai-analysis-v1"]
    disclosure_version: Literal["synthetic-disclosure-v1"]
    budget: AnalysisBudgetV1
    cost_basis: Literal["synthetic_zero_external_cost"]

    @model_validator(mode="after")
    def require_complete_budget_binding(self) -> "AnalysisConsentV1":
        expected = set(AnalysisBudgetV1.model_fields)
        if self.budget.model_fields_set != expected:
            raise ValueError("consent budget 必须显式绑定全部预算字段")
        return self


class AnalysisConsentReceiptV1(AnalysisConsentV1):
    status: Literal["consumed"]
    synthetic: Literal[True]
    provider_calls: int = Field(ge=0)
    network_calls: Literal[0]
    input_tokens: int = Field(ge=0)
    cached_input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    estimated_cost: Literal[0.0]
    latency_ms: int = Field(ge=0)
    fallback: bool
    created_at: datetime
    consumed_at: datetime
    error_code: str | None = None


class ModelCallReceiptV1(StrictModel):
    receipt_id: str
    packet_sha256: str
    provider: Literal["none", "fake"]
    model: str
    prompt_version: str
    schema_version: str
    cache_key: str
    status: Literal[
        "not_called",
        "succeeded",
        "cache_hit",
        "privacy_blocked",
        "budget_blocked",
        "grounding_failed",
        "schema_failed",
        "provider_failed",
    ]
    provider_calls: int = Field(ge=0)
    network_calls: Literal[0]
    synthetic: bool = False
    input_tokens: int = Field(ge=0)
    cached_input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    estimated_cost: float = Field(ge=0)
    latency_ms: int = Field(ge=0)
    error_code: str | None = None
    consent_receipt_id: str | None = None
    client_action_id: str | None = None
    consent_status: Literal["not_required", "consumed"] = "not_required"
    budget: AnalysisBudgetV1 | None = None
    cost_basis: Literal["synthetic_zero_external_cost"] | None = None
    fallback: bool = False
