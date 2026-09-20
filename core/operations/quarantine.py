from __future__ import annotations

import os
from pathlib import Path
import stat


class QuarantineError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def normalized_device_id(value: int) -> int:
    """Project an OS device identifier into SQLite's signed 64-bit INTEGER."""
    normalized = int(value) & ((1 << 64) - 1)
    if normalized > (1 << 63) - 1:
        normalized -= 1 << 64
    return normalized


def _nearest_existing(path: Path) -> Path:
    candidate = path
    while not candidate.exists() and candidate != candidate.parent:
        candidate = candidate.parent
    return candidate


def target_device(quarantine_root: Path) -> int:
    existing = _nearest_existing(quarantine_root)
    return normalized_device_id(existing.stat().st_dev)


def preview_cross_device(source: Path, quarantine_root: Path) -> bool:
    return (
        normalized_device_id(source.stat(follow_symlinks=False).st_dev)
        != normalized_device_id(target_device(quarantine_root))
    )


def quarantine_file(
    *, source: Path, quarantine_root: Path, operation_id: str, asset_id: str
) -> Path:
    info = source.stat(follow_symlinks=False)
    if source.is_symlink() or not stat.S_ISREG(info.st_mode):
        raise QuarantineError("SOURCE_NOT_REGULAR", "源文件不是可隔离的普通文件")
    if normalized_device_id(info.st_dev) != normalized_device_id(
        target_device(quarantine_root)
    ):
        raise QuarantineError("CROSS_DEVICE_UNSUPPORTED", "P0 仅支持同盘原子隔离")
    operation_root = quarantine_root / operation_id
    operation_root.mkdir(parents=True, exist_ok=True)
    destination = operation_root / f"{asset_id}{source.suffix.lower()}"
    if destination.exists():
        raise QuarantineError("QUARANTINE_CONFLICT", "隔离区目标已存在")
    os.replace(source, destination)
    return destination


def restore_file(*, quarantined: Path, original: Path, expected_device: int | None) -> None:
    if not quarantined.exists():
        raise QuarantineError("QUARANTINE_ITEM_MISSING", "隔离区文件不存在")
    if original.exists() or original.is_symlink():
        raise QuarantineError("RESTORE_CONFLICT", "原路径已存在文件，撤销未覆盖")
    if expected_device is not None and normalized_device_id(
        quarantined.stat().st_dev
    ) != normalized_device_id(expected_device):
        raise QuarantineError("RESTORE_DEVICE_CHANGED", "隔离文件所在磁盘已变化")
    parent = original.parent
    if parent.exists() and parent.is_symlink():
        raise QuarantineError("RESTORE_PARENT_UNSAFE", "原目录是符号链接，无法安全恢复")
    parent.mkdir(parents=True, exist_ok=True)
    if normalized_device_id(
        quarantined.stat().st_dev
    ) != normalized_device_id(parent.stat().st_dev):
        raise QuarantineError("CROSS_DEVICE_UNSUPPORTED", "P0 仅支持同盘原子恢复")
    os.replace(quarantined, original)
