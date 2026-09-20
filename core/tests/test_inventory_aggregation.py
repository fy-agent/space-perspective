from __future__ import annotations

from pathlib import Path

from core.collectors.base import ScopeSpec
from core.collectors.filesystem import FileSystemCollector
from core.inventory.aggregation import aggregate_facts, canonical_tree_totals
from core.inventory.snapshots import build_snapshot


def _result(tmp_path: Path):
    root = tmp_path / "fixture"
    (root / "project-alpha").mkdir(parents=True)
    (root / "project-alpha" / "a.txt").write_text("abc", encoding="utf-8")
    (root / "project-alpha" / "b.txt").write_text("defg", encoding="utf-8")
    return FileSystemCollector().collect_all(
        ScopeSpec(scope_id="fixture", root=root, allowed_root=tmp_path)
    )


def test_aggregation_counts_canonical_files_once_and_overlay_does_not_duplicate(
    tmp_path: Path,
) -> None:
    result = _result(tmp_path)
    objects = aggregate_facts(result.facts)
    logical, _ = canonical_tree_totals(result.facts)
    file_logical = sum(
        fact.logical_size_bytes for fact in result.facts if fact.file_type == "file"
    )

    assert logical == file_logical == 7
    assert any(item.object_type == "project" for item in objects)
    assert all(item.reclaimable_estimate_bytes is None for item in objects)
    assert all(item.user_decision is None for item in objects)


def test_snapshot_hash_is_input_order_independent(tmp_path: Path) -> None:
    result = _result(tmp_path)
    first = build_snapshot(
        scan_id="scan-a",
        facts=result.facts,
        coverage=result.coverage,
    )
    second = build_snapshot(
        scan_id="scan-b",
        facts=tuple(reversed(result.facts)),
        coverage=result.coverage,
    )

    assert first.snapshot_sha256 == second.snapshot_sha256
    assert first.snapshot_id == second.snapshot_id
    assert first.content_read is False
    assert first.hash_mode == "none"
