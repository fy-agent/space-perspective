from __future__ import annotations

from core.analysis.packet import build_packet
from core.analysis.privacy import lint_share_safe_packet
from core.tests._inventory_helpers import make_snapshot


def test_privacy_lint_blocks_injected_absolute_path(tmp_path) -> None:
    snapshot, _ = make_snapshot(tmp_path)
    packet = build_packet(
        snapshot,
        artifact_privacy_mode="share_safe",
        analysis_execution_mode="local_only",
    )
    bad = packet.model_copy(
        update={
            "top_objects": [
                packet.top_objects[0].model_copy(
                    update={"display_name": "/Users/private/secret.txt"}
                ),
                *packet.top_objects[1:],
            ]
        }
    )

    result = lint_share_safe_packet(bad)

    assert result.passed is False
    assert "ABSOLUTE_PATH" in result.issue_codes
