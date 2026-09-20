from __future__ import annotations

from core.analysis.packet import build_packet
from core.analysis.privacy import lint_share_safe_packet
from core.tests._inventory_helpers import make_snapshot


def test_packet_hash_is_deterministic_and_share_safe_is_minimized(tmp_path) -> None:
    snapshot, _ = make_snapshot(tmp_path)
    first = build_packet(
        snapshot,
        artifact_privacy_mode="share_safe",
        analysis_execution_mode="local_only",
    )
    second = build_packet(
        snapshot,
        artifact_privacy_mode="share_safe",
        analysis_execution_mode="local_only",
    )
    serialized = first.model_dump_json()

    assert first.packet_sha256 == second.packet_sha256
    assert first.packet_id == second.packet_id
    assert lint_share_safe_packet(first).passed
    assert "alice@example.com" not in serialized
    assert "IGNORE_PREVIOUS" not in serialized
    assert str(tmp_path) not in serialized
    assert all(item.location is None or item.location.startswith("obj_") for item in first.top_objects)


def test_local_full_and_share_safe_keep_same_object_ids(tmp_path) -> None:
    snapshot, _ = make_snapshot(tmp_path)
    local = build_packet(
        snapshot,
        artifact_privacy_mode="local_full",
        analysis_execution_mode="none",
    )
    safe = build_packet(
        snapshot,
        artifact_privacy_mode="share_safe",
        analysis_execution_mode="none",
    )

    assert [item.object_id for item in local.top_objects] == [
        item.object_id for item in safe.top_objects
    ]
    assert lint_share_safe_packet(local).passed is False
    assert lint_share_safe_packet(safe).passed is True
