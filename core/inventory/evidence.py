from __future__ import annotations

from collections import defaultdict
import hashlib

from core.inventory.models import EvidenceV1, GovernanceObjectV1


def _evidence_id(object_id: str, kind: str) -> str:
    return "ev_" + hashlib.sha256(f"{object_id}\0{kind}".encode("utf-8")).hexdigest()[:24]


def build_evidence(objects: list[GovernanceObjectV1]) -> list[EvidenceV1]:
    evidence: list[EvidenceV1] = []
    for item in sorted(objects, key=lambda value: value.object_id):
        evidence.append(
            EvidenceV1(
                evidence_id=_evidence_id(item.object_id, "metadata"),
                object_id=item.object_id,
                fact_ids=item.fact_ids,
                evidence_type="filesystem_metadata",
                statement="空间数字来自零内容读取的文件系统元数据。",
                confidence="high",
                logical_size_bytes=item.logical_size_bytes,
                allocated_size_bytes=item.allocated_size_bytes,
                reclaimable_estimate_bytes=None,
            )
        )
        if item.rule_hints:
            evidence.append(
                EvidenceV1(
                    evidence_id=_evidence_id(item.object_id, "classification"),
                    object_id=item.object_id,
                    fact_ids=item.fact_ids,
                    evidence_type="classification_rule",
                    statement="对象类别来自路径与扩展名规则；不等于用户决定。",
                    confidence="medium",
                    logical_size_bytes=None,
                    allocated_size_bytes=None,
                    reclaimable_estimate_bytes=None,
                )
            )

    candidates: dict[tuple[str, int], list[GovernanceObjectV1]] = defaultdict(list)
    for item in objects:
        if item.object_type in {"file", "archive", "installer"}:
            suffix = item.name.rsplit(".", 1)[-1].casefold() if "." in item.name else ""
            candidates[(suffix, item.logical_size_bytes)].append(item)
    for group in candidates.values():
        if len(group) < 2:
            continue
        for item in sorted(group, key=lambda value: value.object_id):
            evidence.append(
                EvidenceV1(
                    evidence_id=_evidence_id(item.object_id, "possible-duplicate"),
                    object_id=item.object_id,
                    fact_ids=[
                        fact_id
                        for member in sorted(group, key=lambda value: value.object_id)
                        for fact_id in member.fact_ids
                    ],
                    evidence_type="possible_duplicate",
                    statement="扩展名与逻辑大小相同：可能重复，尚未核验。",
                    confidence="low",
                    logical_size_bytes=item.logical_size_bytes,
                    allocated_size_bytes=None,
                    reclaimable_estimate_bytes=None,
                )
            )
    return sorted(evidence, key=lambda item: item.evidence_id)
