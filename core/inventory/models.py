from __future__ import annotations

from datetime import datetime
import hashlib
import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


SCHEMA_VERSION = "1.0"
INVENTORY_PROFILE = "inventory_metadata"
HASH_MODE = "none"

ObjectType = Literal[
    "volume",
    "directory",
    "application",
    "game_library",
    "cache_group",
    "package_manager_store",
    "local_model",
    "project",
    "archive",
    "installer",
    "file",
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


def canonical_json(value: BaseModel | dict[str, Any] | list[Any]) -> str:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def canonical_sha256(value: BaseModel | dict[str, Any] | list[Any]) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


class TimeEvidenceV1(StrictModel):
    value: datetime | None
    source: str
    evidence_type: Literal[
        "filesystem_birthtime",
        "filesystem_status_change",
        "filesystem_modified",
        "filesystem_access",
        "unavailable",
    ]
    confidence: Literal["high", "medium", "low", "unknown"]
    platform: str
    limitation: str | None


class ScanFactV1(StrictModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    fact_id: str
    scope_id: str
    profile: Literal["inventory_metadata"] = INVENTORY_PROFILE
    relative_path: str
    absolute_path: str
    name: str
    parent_relative_path: str | None
    file_type: Literal["file", "directory", "symlink", "other"]
    status: Literal["collected", "skipped", "permission_denied", "cancelled"]
    error_code: str | None = None
    logical_size_bytes: int = Field(ge=0)
    allocated_size_bytes: int | None = Field(default=None, ge=0)
    reclaimable_estimate_bytes: int | None = Field(default=None, ge=0)
    extension: str
    modified: TimeEvidenceV1
    created: TimeEvidenceV1
    accessed: TimeEvidenceV1
    platform: str
    content_read: Literal[False] = False
    hash_mode: Literal["none"] = HASH_MODE


class RuleHintV1(StrictModel):
    rule_id: str
    rules_version: str
    message: str
    priority: Literal["建议先看", "有空再看", "留意即可"]


class GovernanceObjectV1(StrictModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    object_id: str
    object_type: ObjectType
    parent_object_id: str | None
    fact_ids: list[str] = Field(min_length=1)
    name: str
    relative_path: str
    absolute_path: str
    logical_size_bytes: int = Field(ge=0)
    allocated_size_bytes: int | None = Field(default=None, ge=0)
    reclaimable_estimate_bytes: int | None = Field(default=None, ge=0)
    created: TimeEvidenceV1
    modified: TimeEvidenceV1
    accessed: TimeEvidenceV1
    rule_hints: list[RuleHintV1] = Field(default_factory=list)
    user_decision: None = None
    user_note: None = None


class EvidenceV1(StrictModel):
    evidence_id: str
    object_id: str
    fact_ids: list[str] = Field(min_length=1)
    evidence_type: Literal[
        "filesystem_metadata",
        "classification_rule",
        "possible_duplicate",
        "permission_gap",
    ]
    statement: str
    confidence: Literal["high", "medium", "low", "unknown"]
    logical_size_bytes: int | None = Field(default=None, ge=0)
    allocated_size_bytes: int | None = Field(default=None, ge=0)
    reclaimable_estimate_bytes: int | None = Field(default=None, ge=0)


class CoverageV1(StrictModel):
    requested_entries: int = Field(ge=0)
    collected_entries: int = Field(ge=0)
    skipped_entries: int = Field(ge=0)
    permission_gaps: list[str] = Field(default_factory=list)
    cancelled: bool = False


class ReportSnapshotV1(StrictModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    snapshot_id: str
    snapshot_sha256: str
    scan_id: str
    generated_at: datetime
    profile: Literal["inventory_metadata"] = INVENTORY_PROFILE
    platform: str
    rules_version: str
    content_read: Literal[False] = False
    hash_mode: Literal["none"] = HASH_MODE
    canonical_tree_logical_size_bytes: int = Field(ge=0)
    canonical_tree_allocated_size_bytes: int | None = Field(default=None, ge=0)
    reclaimable_estimate_bytes: int | None = Field(default=None, ge=0)
    coverage: CoverageV1
    limitations: list[str]
    objects: list[GovernanceObjectV1]
    evidence: list[EvidenceV1]
