from __future__ import annotations

import ctypes
from datetime import datetime, timezone
import os
from pathlib import Path
from typing import Callable

from core.collectors.platform.base import PlatformMetadata
from core.inventory.models import TimeEvidenceV1


AllocatedSizeReader = Callable[[Path], int | None]


def _datetime(value: float) -> datetime:
    return datetime.fromtimestamp(value, timezone.utc)


def windows_extended_path(path: str | Path) -> str:
    value = str(path)
    if value.startswith("\\\\?\\"):
        return value
    if value.startswith("\\\\"):
        return "\\\\?\\UNC\\" + value[2:]
    return "\\\\?\\" + value


def _native_allocated_size(path: Path) -> int:
    if os.name != "nt":
        raise OSError("NATIVE_WINDOWS_REQUIRED")
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_compressed_file_size = kernel32.GetCompressedFileSizeW
    get_compressed_file_size.argtypes = [
        wintypes.LPCWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    get_compressed_file_size.restype = wintypes.DWORD
    high = wintypes.DWORD()
    ctypes.set_last_error(0)
    low = get_compressed_file_size(
        windows_extended_path(path),
        ctypes.byref(high),
    )
    error = ctypes.get_last_error()
    if low == 0xFFFFFFFF and error:
        raise ctypes.WinError(error)
    return (int(high.value) << 32) | int(low)


class WindowsMetadataAdapter:
    platform_name = "windows"
    native_validated = os.name == "nt"

    def __init__(
        self,
        *,
        allocated_size_reader: AllocatedSizeReader | None = None,
    ):
        self._allocated_size_reader = (
            allocated_size_reader or _native_allocated_size
        )

    def from_stat(self, path: Path, info: os.stat_result) -> PlatformMetadata:
        try:
            allocated = self._allocated_size_reader(path)
        except OSError:
            allocated = None
        birthtime = getattr(info, "st_birthtime", None)
        if birthtime is not None:
            created = TimeEvidenceV1(
                value=_datetime(birthtime),
                source="stat.st_birthtime",
                evidence_type="filesystem_birthtime",
                confidence="high",
                platform=self.platform_name,
                limitation=(
                    "Windows 文件系统 creation time；复制或恢复可能改变该值。"
                ),
            )
        else:
            created = TimeEvidenceV1(
                value=_datetime(info.st_ctime),
                source="stat.st_ctime",
                evidence_type="filesystem_birthtime",
                confidence="medium",
                platform=self.platform_name,
                limitation=(
                    "Windows st_ctime 在当前 Python 版本表示 creation time；"
                    "优先使用 st_birthtime 的环境可获得更明确来源。"
                ),
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
                limitation=(
                    "Windows last-access update 可能被禁用或延迟，不等同于最后打开。"
                ),
            ),
        )
