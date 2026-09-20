from __future__ import annotations

from core.analysis.packet import build_packet
from core.analysis.privacy import lint_share_safe_packet
from core.tests._inventory_helpers import make_snapshot


def test_share_safe_packet_has_no_secret_path_or_content_fields(tmp_path) -> None:
    snapshot, _ = make_snapshot(tmp_path)
    packet = build_packet(
        snapshot,
        artifact_privacy_mode="share_safe",
        analysis_execution_mode="local_only",
    )
    payload = packet.model_dump()

    assert lint_share_safe_packet(packet).passed
    assert "absolute_path" not in str(payload)
    assert "file_hash" not in str(payload)
    assert "file_content" not in str(payload)


def test_cloud_contract_packet_remains_share_safe_and_offline(tmp_path) -> None:
    snapshot, _ = make_snapshot(tmp_path)
    packet = build_packet(
        snapshot,
        artifact_privacy_mode="share_safe",
        analysis_execution_mode="cloud_metadata_minimized",
    )
    serialized = packet.model_dump_json()

    assert lint_share_safe_packet(packet).passed
    assert packet.analysis_execution_mode == "cloud_metadata_minimized"
    assert str(tmp_path) not in serialized
    assert "file_content" not in serialized
    assert "file_hash" not in serialized
