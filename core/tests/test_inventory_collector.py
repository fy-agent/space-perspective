from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from core.collectors.base import CancelToken, ScopeSpec
from core.collectors.checkpoint import CollectorCheckpointError
from core.collectors.filesystem import FileSystemCollector
from core.collectors.platform.macos import MacOSMetadataAdapter
import core.scanner.hashing as p0_hashing


def test_inventory_metadata_reads_no_content_or_hash_and_preserves_fixture(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "fixture"
    root.mkdir()
    sample = root / "sample.txt"
    sample.write_text("controlled", encoding="utf-8")
    before = (sample.read_bytes(), sample.stat().st_mtime_ns, sample.stat().st_size)
    partial = Mock(side_effect=AssertionError("P0 hash helper must not be called"))
    full = Mock(side_effect=AssertionError("P0 hash helper must not be called"))
    monkeypatch.setattr(p0_hashing, "partial_sha256", partial)
    monkeypatch.setattr(p0_hashing, "full_sha256", full)

    content_open = Mock(side_effect=AssertionError("product content read is forbidden"))
    with monkeypatch.context() as scoped:
        scoped.setattr(Path, "open", content_open)
        result = FileSystemCollector().collect_all(
            ScopeSpec(scope_id="fixture", root=root, allowed_root=tmp_path)
        )

    after = (sample.read_bytes(), sample.stat().st_mtime_ns, sample.stat().st_size)
    assert before == after
    assert result.counters.product_content_reads == 0
    assert result.counters.product_file_hashes == 0
    assert result.counters.network_calls == 0
    assert partial.call_count == full.call_count == 0
    assert content_open.call_count == 0
    assert all(fact.content_read is False and fact.hash_mode == "none" for fact in result.facts)


def test_symlink_is_visible_but_not_followed(tmp_path: Path) -> None:
    root = tmp_path / "fixture"
    root.mkdir()
    target = root / "target"
    target.mkdir()
    (target / "inside.txt").write_text("x", encoding="utf-8")
    (root / "loop").symlink_to(root, target_is_directory=True)

    result = FileSystemCollector().collect_all(
        ScopeSpec(scope_id="fixture", root=root, allowed_root=tmp_path)
    )

    loop = next(fact for fact in result.facts if fact.name == "loop")
    assert loop.file_type == "symlink"
    assert loop.status == "skipped"
    assert loop.error_code == "SYMLINK_NOT_FOLLOWED"
    assert [fact.name for fact in result.facts].count("inside.txt") == 1


def test_cancel_has_structured_checkpoint(tmp_path: Path) -> None:
    root = tmp_path / "fixture"
    root.mkdir()
    (root / "sample.txt").write_text("x", encoding="utf-8")
    token = CancelToken(cancelled=True)

    result = FileSystemCollector().collect_all(
        ScopeSpec(scope_id="fixture", root=root, allowed_root=tmp_path),
        cancel_token=token,
    )

    assert result.checkpoint.status == "cancelled"
    assert result.coverage.cancelled is True
    assert result.facts == ()


def test_permission_gap_is_visible(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "fixture"
    root.mkdir()
    denied = root / "denied.txt"
    denied.write_text("x", encoding="utf-8")
    original = Path.stat

    def controlled_stat(path: Path, *args, **kwargs):
        if path == denied:
            raise PermissionError("controlled")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", controlled_stat)
    result = FileSystemCollector().collect_all(
        ScopeSpec(
            scope_id="fixture",
            root=root,
            allowed_root=tmp_path,
            manifest_entries=("denied.txt",),
        )
    )

    assert result.coverage.permission_gaps == ["denied.txt"]
    assert result.facts[0].status == "permission_denied"
    assert result.checkpoint.status == "partial"


def test_macos_adapter_does_not_treat_ctime_as_creation() -> None:
    info = SimpleNamespace(st_blocks=1, st_mtime=2.0, st_atime=1.0, st_ctime=3.0)

    metadata = MacOSMetadataAdapter().from_stat(Path("/controlled"), info)

    assert metadata.created.value is None
    assert metadata.created.evidence_type == "unavailable"
    assert "ctime" in (metadata.created.limitation or "")


def test_cancelled_manifest_collection_resumes_without_duplicates_or_gaps(
    tmp_path: Path,
) -> None:
    root = tmp_path / "fixture"
    root.mkdir()
    entries = tuple(f"item-{index:02d}.txt" for index in range(7))
    for relative in entries:
        (root / relative).write_text(relative, encoding="utf-8")
    scope = ScopeSpec(
        scope_id="scan_resume_fixture",
        root=root,
        allowed_root=tmp_path,
        manifest_entries=entries,
    )

    token = CancelToken()
    stream = FileSystemCollector(batch_size=3).collect(
        scope,
        "inventory_metadata",
        None,
        token,
    )
    first = next(stream)
    token.cancel()
    cancelled = list(stream)[-1]

    assert cancelled.checkpoint.status == "cancelled"
    assert cancelled.checkpoint.collected_entries == 3
    assert cancelled.coverage.collected_entries == 3

    resumed = FileSystemCollector(batch_size=2).collect_all(
        scope,
        checkpoint=cancelled.checkpoint,
    )
    complete = FileSystemCollector(batch_size=2).collect_all(scope)
    combined = (*first.facts, *resumed.facts)

    assert resumed.checkpoint.status == "completed"
    assert resumed.coverage.collected_entries == len(entries)
    assert [fact.fact_id for fact in combined] == [
        fact.fact_id for fact in complete.facts
    ]
    assert [fact.relative_path for fact in combined] == list(entries)
    assert len({fact.fact_id for fact in combined}) == len(entries)


def test_resume_rejects_scope_status_cursor_and_manifest_mismatch(
    tmp_path: Path,
) -> None:
    root = tmp_path / "fixture"
    root.mkdir()
    entries = ("a.txt", "b.txt", "c.txt")
    for relative in entries:
        (root / relative).write_text(relative, encoding="utf-8")
    scope = ScopeSpec(
        scope_id="scan_resume_validation",
        root=root,
        allowed_root=tmp_path,
        manifest_entries=entries,
    )
    token = CancelToken()
    stream = FileSystemCollector(batch_size=1).collect(
        scope,
        "inventory_metadata",
        None,
        token,
    )
    next(stream)
    token.cancel()
    checkpoint = list(stream)[-1].checkpoint

    cancelled_again = FileSystemCollector().collect_all(
        scope,
        checkpoint=checkpoint,
        cancel_token=CancelToken(cancelled=True),
    )
    assert cancelled_again.checkpoint.status == "cancelled"
    assert cancelled_again.facts == ()

    with pytest.raises(CollectorCheckpointError, match="scan_id"):
        FileSystemCollector().collect_all(
            ScopeSpec(
                scope_id="scan_other",
                root=root,
                allowed_root=tmp_path,
                manifest_entries=entries,
            ),
            checkpoint=checkpoint,
        )

    with pytest.raises(CollectorCheckpointError, match="status"):
        FileSystemCollector().collect_all(
            scope,
            checkpoint=checkpoint.model_copy(update={"status": "completed"}),
        )

    with pytest.raises(CollectorCheckpointError, match="cursor"):
        FileSystemCollector().collect_all(
            scope,
            checkpoint=checkpoint.model_copy(
                update={"last_relative_path": "missing.txt"}
            ),
        )

    with pytest.raises(CollectorCheckpointError, match="fingerprint"):
        FileSystemCollector().collect_all(
            ScopeSpec(
                scope_id=scope.scope_id,
                root=root,
                allowed_root=tmp_path,
                manifest_entries=(*entries, "new.txt"),
            ),
            checkpoint=checkpoint,
        )

    other_root = tmp_path / "other-fixture"
    other_root.mkdir()
    for relative in entries:
        (other_root / relative).write_text(relative, encoding="utf-8")
    with pytest.raises(CollectorCheckpointError, match="fingerprint"):
        FileSystemCollector().collect_all(
            ScopeSpec(
                scope_id=scope.scope_id,
                root=other_root,
                allowed_root=tmp_path,
                manifest_entries=entries,
            ),
            checkpoint=checkpoint,
        )
