from pathlib import Path

import pytest

from core.operations.quarantine import (
    QuarantineError,
    normalized_device_id,
    quarantine_file,
)


def test_unsigned_windows_device_id_projects_to_sqlite_int64() -> None:
    assert normalized_device_id(0) == 0
    assert normalized_device_id((1 << 63) - 1) == (1 << 63) - 1
    assert normalized_device_id(1 << 63) == -(1 << 63)
    assert normalized_device_id((1 << 64) - 1) == -1


def test_cross_device_quarantine_rejects_without_touching_source(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "source.txt"
    source.write_text("must remain in place", encoding="utf-8")
    source_device = source.stat().st_dev
    monkeypatch.setattr(
        "core.operations.quarantine.target_device",
        lambda _root: source_device + 1,
    )

    with pytest.raises(QuarantineError) as captured:
        quarantine_file(
            source=source,
            quarantine_root=tmp_path / "other-volume",
            operation_id="op-test",
            asset_id="asset-test",
        )

    assert captured.value.code == "CROSS_DEVICE_UNSUPPORTED"
    assert source.read_text(encoding="utf-8") == "must remain in place"
    assert not (tmp_path / "other-volume").exists()
