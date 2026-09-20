from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field

from core.inventory.models import StrictModel


SHEET_NAMES = [
    "空间体检概览",
    "空间明细清单",
    "建议优先查看",
    "可能重复与安装包",
    "报告说明与记录",
]


class ReportManifestV1(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    report_schema_version: Literal["1.0"] = "1.0"
    report_id: str
    artifact_id: str
    snapshot_id: str
    packet_id: str
    analysis_id: str
    generated_at: datetime
    artifact_privacy_mode: Literal["local_full", "share_safe"]
    provider: Literal["none", "fake"]
    analysis_status: Literal["deterministic_only", "ai_complete", "ai_failed_fallback"]
    filename: str
    workbook_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    sheets: list[str] = Field(default_factory=lambda: list(SHEET_NAMES))
    zip_integrity: Literal[True] = True
    reopen_validated: Literal[True] = True
