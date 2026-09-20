from __future__ import annotations

import hashlib
from pathlib import PurePosixPath

from core.inventory.classification import classify_fact, rule_hints_for
from core.inventory.models import GovernanceObjectV1, ScanFactV1


def _object_id(fact: ScanFactV1) -> str:
    payload = f"{fact.relative_path}\0{fact.file_type}".encode("utf-8")
    return "obj_" + hashlib.sha256(payload).hexdigest()[:24]


def aggregate_facts(facts: list[ScanFactV1] | tuple[ScanFactV1, ...]) -> list[GovernanceObjectV1]:
    collected = [fact for fact in facts if fact.status == "collected"]
    by_relative = {fact.relative_path: fact for fact in collected}
    id_by_relative = {relative: _object_id(fact) for relative, fact in by_relative.items()}
    file_facts = [fact for fact in collected if fact.file_type == "file"]
    objects: list[GovernanceObjectV1] = []

    for fact in sorted(collected, key=lambda item: (item.relative_path.casefold(), item.fact_id)):
        if fact.file_type == "directory":
            prefix = fact.relative_path.rstrip("/") + "/"
            descendants = [
                item
                for item in file_facts
                if item.relative_path.startswith(prefix)
            ]
            logical = sum(item.logical_size_bytes for item in descendants)
            if descendants and all(item.allocated_size_bytes is not None for item in descendants):
                allocated = sum(int(item.allocated_size_bytes or 0) for item in descendants)
            elif descendants:
                allocated = None
            else:
                allocated = 0
        else:
            logical = fact.logical_size_bytes
            allocated = fact.allocated_size_bytes

        parent_relative = fact.parent_relative_path
        parent_id = id_by_relative.get(parent_relative) if parent_relative else None
        object_type = classify_fact(fact)
        objects.append(
            GovernanceObjectV1(
                object_id=id_by_relative[fact.relative_path],
                object_type=object_type,
                parent_object_id=parent_id,
                fact_ids=[fact.fact_id],
                name=fact.name,
                relative_path=fact.relative_path,
                absolute_path=fact.absolute_path,
                logical_size_bytes=logical,
                allocated_size_bytes=allocated,
                reclaimable_estimate_bytes=None,
                created=fact.created,
                modified=fact.modified,
                accessed=fact.accessed,
                rule_hints=rule_hints_for(object_type),
            )
        )
    return objects


def canonical_tree_totals(
    facts: list[ScanFactV1] | tuple[ScanFactV1, ...],
) -> tuple[int, int | None]:
    files = [
        fact
        for fact in facts
        if fact.status == "collected" and fact.file_type == "file"
    ]
    logical = sum(fact.logical_size_bytes for fact in files)
    if all(fact.allocated_size_bytes is not None for fact in files):
        allocated = sum(int(fact.allocated_size_bytes or 0) for fact in files)
    else:
        allocated = None
    return logical, allocated
