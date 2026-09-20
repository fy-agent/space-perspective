from __future__ import annotations

from typing import Literal

from core.analysis.minimization import normalized_label, pseudonym
from core.analysis.schemas import (
    AnalysisPacketV1,
    CoverageSummaryV1,
    LongTailV1,
    PacketObjectV1,
)
from core.inventory.models import ReportSnapshotV1, canonical_sha256


def build_packet(
    snapshot: ReportSnapshotV1,
    *,
    artifact_privacy_mode: Literal["local_full", "share_safe"],
    analysis_execution_mode: Literal[
        "none",
        "local_only",
        "cloud_metadata_minimized",
    ],
    top_k: int = 200,
) -> AnalysisPacketV1:
    if not 1 <= top_k <= 200:
        raise ValueError("top_k 必须在 1..200")
    if (
        analysis_execution_mode == "cloud_metadata_minimized"
        and artifact_privacy_mode != "share_safe"
    ):
        raise ValueError("cloud_metadata_minimized 只允许 share_safe packet")
    evidence_by_object: dict[str, list[str]] = {}
    for evidence in snapshot.evidence:
        evidence_by_object.setdefault(evidence.object_id, []).append(evidence.evidence_id)
    ordered = sorted(
        snapshot.objects,
        key=lambda item: (-item.logical_size_bytes, item.object_id),
    )
    selected = ordered[:top_k]
    packet_objects: list[PacketObjectV1] = []
    for index, item in enumerate(selected, start=1):
        local = artifact_privacy_mode == "local_full"
        packet_objects.append(
            PacketObjectV1(
                object_id=item.object_id,
                evidence_ids=sorted(evidence_by_object.get(item.object_id, [])),
                object_type=item.object_type,
                display_name=(
                    normalized_label(item.name)
                    if local
                    else pseudonym(item.object_type, index)
                ),
                location=(
                    normalized_label(item.absolute_path, limit=512)
                    if local
                    else item.parent_object_id
                ),
                name_length=len(item.name),
                logical_size_bytes=item.logical_size_bytes,
                allocated_size_bytes=item.allocated_size_bytes,
                reclaimable_estimate_bytes=item.reclaimable_estimate_bytes,
                rule_hints=[
                    normalized_label(hint.message, limit=240)
                    for hint in item.rule_hints
                ],
            )
        )
    long_tail_items = ordered[top_k:]
    long_tail = LongTailV1(
        object_count=len(long_tail_items),
        logical_size_bytes=sum(item.logical_size_bytes for item in long_tail_items),
    )
    fingerprint = {
        "schema_version": "1.0",
        "snapshot_id": snapshot.snapshot_id,
        "snapshot_sha256": snapshot.snapshot_sha256,
        "artifact_privacy_mode": artifact_privacy_mode,
        "analysis_execution_mode": analysis_execution_mode,
        "profile": snapshot.profile,
        "platform": snapshot.platform,
        "content_read": False,
        "hash_mode": "none",
        "canonical_tree_logical_size_bytes": snapshot.canonical_tree_logical_size_bytes,
        "canonical_tree_allocated_size_bytes": snapshot.canonical_tree_allocated_size_bytes,
        "reclaimable_estimate_bytes": snapshot.reclaimable_estimate_bytes,
        "coverage_summary": {
            "requested_entries": snapshot.coverage.requested_entries,
            "collected_entries": snapshot.coverage.collected_entries,
            "skipped_entries": snapshot.coverage.skipped_entries,
            "permission_gap_count": len(snapshot.coverage.permission_gaps),
            "cancelled": snapshot.coverage.cancelled,
        },
        "limitations": snapshot.limitations,
        "top_objects": [
            item.model_dump(mode="json") for item in packet_objects
        ],
        "long_tail": long_tail.model_dump(mode="json"),
        "truncated": len(ordered) > top_k,
    }
    digest = canonical_sha256(fingerprint)
    return AnalysisPacketV1(
        packet_id=f"packet_{digest[:24]}",
        packet_sha256=digest,
        snapshot_id=snapshot.snapshot_id,
        snapshot_sha256=snapshot.snapshot_sha256,
        generated_at=snapshot.generated_at,
        artifact_privacy_mode=artifact_privacy_mode,
        analysis_execution_mode=analysis_execution_mode,
        platform=snapshot.platform,
        canonical_tree_logical_size_bytes=snapshot.canonical_tree_logical_size_bytes,
        canonical_tree_allocated_size_bytes=snapshot.canonical_tree_allocated_size_bytes,
        reclaimable_estimate_bytes=snapshot.reclaimable_estimate_bytes,
        coverage_summary=CoverageSummaryV1(**fingerprint["coverage_summary"]),
        limitations=snapshot.limitations,
        top_objects=packet_objects,
        long_tail=long_tail,
        truncated=len(ordered) > top_k,
    )


def build_packet_pair(
    snapshot: ReportSnapshotV1,
    *,
    analysis_execution_mode: Literal[
        "none",
        "local_only",
        "cloud_metadata_minimized",
    ],
    top_k: int = 200,
) -> tuple[AnalysisPacketV1, AnalysisPacketV1]:
    return (
        build_packet(
            snapshot,
            artifact_privacy_mode="local_full",
            analysis_execution_mode=analysis_execution_mode,
            top_k=top_k,
        ),
        build_packet(
            snapshot,
            artifact_privacy_mode="share_safe",
            analysis_execution_mode=analysis_execution_mode,
            top_k=top_k,
        ),
    )
