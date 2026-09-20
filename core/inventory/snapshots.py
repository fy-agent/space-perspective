from __future__ import annotations

from datetime import datetime, timezone

from core.inventory.aggregation import aggregate_facts, canonical_tree_totals
from core.inventory.classification import RULES_VERSION
from core.inventory.evidence import build_evidence
from core.inventory.models import (
    CoverageV1,
    ReportSnapshotV1,
    ScanFactV1,
    canonical_sha256,
)


def build_snapshot(
    *,
    scan_id: str,
    facts: list[ScanFactV1] | tuple[ScanFactV1, ...],
    coverage: CoverageV1,
    generated_at: datetime | None = None,
) -> ReportSnapshotV1:
    objects = aggregate_facts(facts)
    evidence = build_evidence(objects)
    logical, allocated = canonical_tree_totals(facts)
    platform = next((fact.platform for fact in facts), "unknown")
    limitations = [
        "inventory_metadata 不读取文件内容，也不计算文件 hash。",
        "可能重复仅来自元数据线索，尚未核验。",
        "可能可腾出未评估，因此保持 null。",
        "atime 只作为低可信活动线索，不等同于最后打开。",
    ]
    if allocated is None:
        limitations.append(
            "至少一个文件未取得原生 allocated size，因此汇总实际占用保持 null。"
        )
    fingerprint_payload = {
        "schema_version": "1.0",
        "profile": "inventory_metadata",
        "platform": platform,
        "rules_version": RULES_VERSION,
        "content_read": False,
        "hash_mode": "none",
        "canonical_tree_logical_size_bytes": logical,
        "canonical_tree_allocated_size_bytes": allocated,
        "reclaimable_estimate_bytes": None,
        "coverage": coverage.model_dump(mode="json"),
        "limitations": limitations,
        "objects": [
            item.model_dump(mode="json")
            for item in sorted(objects, key=lambda value: value.object_id)
        ],
        "evidence": [
            item.model_dump(mode="json")
            for item in sorted(evidence, key=lambda value: value.evidence_id)
        ],
    }
    digest = canonical_sha256(fingerprint_payload)
    return ReportSnapshotV1(
        snapshot_id=f"snapshot_{digest[:24]}",
        snapshot_sha256=digest,
        scan_id=scan_id,
        generated_at=generated_at or datetime.now(timezone.utc),
        platform=platform,
        rules_version=RULES_VERSION,
        canonical_tree_logical_size_bytes=logical,
        canonical_tree_allocated_size_bytes=allocated,
        reclaimable_estimate_bytes=None,
        coverage=coverage,
        limitations=limitations,
        objects=sorted(objects, key=lambda item: item.object_id),
        evidence=sorted(evidence, key=lambda item: item.evidence_id),
    )
