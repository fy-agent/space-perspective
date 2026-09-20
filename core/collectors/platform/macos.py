from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import os

from core.collectors.platform.base import PlatformMetadata
from core.inventory.models import TimeEvidenceV1


def _datetime(value: float) -> datetime:
    return datetime.fromtimestamp(value, timezone.utc)


class MacOSMetadataAdapter:
    platform_name = "macos"
    native_validated = True

    def from_stat(self, path: Path, info: os.stat_result) -> PlatformMetadata:
        blocks = getattr(info, "st_blocks", None)
        allocated = int(blocks * 512) if blocks is not None else None
        birthtime = getattr(info, "st_birthtime", None)
        if birthtime is None:
            created = TimeEvidenceV1(
                value=None,
                source="unavailable",
                evidence_type="unavailable",
                confidence="unknown",
                platform=self.platform_name,
                limitation="当前文件系统未提供 birthtime；ctime 不作为创建时间。",
            )
        else:
            created = TimeEvidenceV1(
                value=_datetime(birthtime),
                source="stat.st_birthtime",
                evidence_type="filesystem_birthtime",
                confidence="medium",
                platform=self.platform_name,
                limitation="birthtime 由当前文件系统提供，跨平台不可直接类比。",
            )
        return PlatformMetadata(
            allocated_size_bytes=allocated,
            created=created,
            modified=TimeEvidenceV1(
                value=_datetime(info.st_mtime),
                source="stat.st_mtime",
                evidence_type="filesystem_modified",
                confidence="high",
                platform=self.platform_name,
                limitation=None,
            ),
            accessed=TimeEvidenceV1(
                value=_datetime(info.st_atime),
                source="stat.st_atime",
                evidence_type="filesystem_access",
                confidence="low",
                platform=self.platform_name,
                limitation="atime 可能被禁用、延迟或因元数据访问更新，不等同于最后打开。",
            ),
        )
