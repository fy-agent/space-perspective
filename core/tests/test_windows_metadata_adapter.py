from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from core.collectors.filesystem import FileSystemCollector, default_metadata_adapter
from core.collectors.platform.windows import (
    WindowsMetadataAdapter,
    windows_extended_path,
)


def _stat(**overrides):
    values = {
        "st_size": 123,
        "st_mtime": 20.0,
        "st_atime": 10.0,
        "st_ctime": 30.0,
        "st_birthtime": 40.0,
        "st_mode": 0o100644,
        "st_file_attributes": 0,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_windows_adapter_uses_native_allocation_and_birthtime() -> None:
    adapter = WindowsMetadataAdapter(
        allocated_size_reader=lambda path: 4_096 if path.name == "受控.txt" else None
    )

    metadata = adapter.from_stat(Path("受控.txt"), _stat())

    assert metadata.allocated_size_bytes == 4_096
    assert metadata.created.value.timestamp() == 40.0
    assert metadata.created.source == "stat.st_birthtime"
    assert metadata.created.evidence_type == "filesystem_birthtime"
    assert metadata.created.platform == "windows"
    assert metadata.modified.value.timestamp() == 20.0
    assert metadata.accessed.confidence == "low"


def test_windows_adapter_falls_back_without_claiming_allocated_size() -> None:
    def unavailable(_path: Path) -> int | None:
        raise OSError("controlled native API failure")

    info = _stat()
    del info.st_birthtime
    metadata = WindowsMetadataAdapter(
        allocated_size_reader=unavailable
    ).from_stat(Path("controlled.txt"), info)

    assert metadata.allocated_size_bytes is None
    assert metadata.created.value.timestamp() == 30.0
    assert metadata.created.source == "stat.st_ctime"
    assert "Windows" in (metadata.created.limitation or "")


def test_windows_extended_path_handles_drive_and_unc_paths() -> None:
    assert windows_extended_path(r"C:\fixture\资料.txt") == r"\\?\C:\fixture\资料.txt"
    assert (
        windows_extended_path(r"\\server\share\资料.txt")
        == r"\\?\UNC\server\share\资料.txt"
    )
    assert windows_extended_path(r"\\?\C:\already.txt") == r"\\?\C:\already.txt"


def test_default_adapter_selects_windows_without_changing_public_schema() -> None:
    adapter = default_metadata_adapter("win32")

    assert isinstance(adapter, WindowsMetadataAdapter)
    assert adapter.platform_name == "windows"
    assert FileSystemCollector._file_type(
        _stat(st_file_attributes=0x400, st_mode=0o040755)
    ) == "symlink"
