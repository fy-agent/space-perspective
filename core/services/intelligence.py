from __future__ import annotations

from collections import defaultdict
import json
from pathlib import Path
from typing import Any

from core.db.repository import Repository, new_id, utc_now
from core.domain.rules import assess_risk
from core.scanner.hashing import full_sha256, partial_sha256


RULE_VERSION = "p0-rules-v1"


def _keep_sort_key(asset: dict[str, Any]) -> tuple[Any, ...]:
    name = Path(asset["abs_path"]).stem.casefold()
    copy_marker = any(marker in name for marker in ("copy", "副本", "重复", "复件", "(1)", "-1"))
    source_priority = {
        "documents": 0, "pictures": 1, "manual_folder": 2, "wechat": 3,
        "suspected_wechat": 4, "desktop": 5, "downloads": 6, "unknown": 7,
    }.get(asset["source_hint"], 8)
    return (
        0 if asset["risk_level"] == "high" else 1,
        source_priority,
        1 if copy_marker else 0,
        -(asset.get("modified_ns") or 0),
        len(asset["abs_path"]),
        asset["id"],
    )


def build_intelligence(repository: Repository, scan_id: str, compute_hash: bool) -> None:
    repository.clear_intelligence(scan_id)
    assets = repository.list_asset_rows(scan_id)
    session = repository.get_scan(scan_id)
    roots = [Path(value) for value in session.requested_paths] if session else []
    exact_by_asset: dict[str, tuple[str, bool]] = {}

    def risk_subject(asset: dict[str, Any]) -> Path:
        absolute = Path(asset["abs_path"])
        for root in roots:
            try:
                return absolute.relative_to(root)
            except ValueError:
                continue
        return Path(absolute.name)

    if compute_hash:
        size_buckets: dict[int, list[dict[str, Any]]] = defaultdict(list)
        for asset in assets:
            size_buckets[int(asset["size_bytes"])].append(asset)
        for candidates in size_buckets.values():
            if len(candidates) < 2:
                continue
            partial_buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for asset in candidates:
                try:
                    partial = partial_sha256(Path(asset["abs_path"]), int(asset["size_bytes"]))
                    repository.update_asset_hash(
                        asset["id"], partial_hash=partial, file_hash=None, hash_status="partial"
                    )
                    asset["partial_hash"] = partial
                    partial_buckets[partial].append(asset)
                except OSError:
                    repository.update_asset_hash(
                        asset["id"], partial_hash=None, file_hash=None, hash_status="failed"
                    )
            for partial_group in partial_buckets.values():
                if len(partial_group) < 2:
                    continue
                full_buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
                for asset in partial_group:
                    try:
                        digest = full_sha256(Path(asset["abs_path"]))
                        repository.update_asset_hash(
                            asset["id"], partial_hash=asset["partial_hash"], file_hash=digest,
                            hash_status="full",
                        )
                        asset["file_hash"] = digest
                        asset["hash_status"] = "full"
                        full_buckets[digest].append(asset)
                    except OSError:
                        repository.update_asset_hash(
                            asset["id"], partial_hash=asset["partial_hash"], file_hash=None,
                            hash_status="failed",
                        )
                for digest, duplicates in full_buckets.items():
                    if len(duplicates) < 2:
                        continue
                    for asset in duplicates:
                        risk, flags = assess_risk(risk_subject(asset), has_exact_duplicate=True)
                        asset["risk_level"] = risk
                        asset["risk_flags_json"] = json.dumps(flags, ensure_ascii=False)
                        repository.update_asset_risk(asset["id"], risk, flags)
                    keep = min(duplicates, key=_keep_sort_key)
                    group_id = new_id("dup")
                    total = sum(int(item["size_bytes"]) for item in duplicates)
                    reclaimable = total - int(keep["size_bytes"])
                    repository.insert_duplicate_group(
                        {
                            "id": group_id, "scan_session_id": scan_id, "file_hash": digest,
                            "keep_asset_id": keep["id"],
                            "reason": "优先保留敏感或重要来源中的稳定版本；再按文件名、修改时间和路径长度排序。",
                            "total_size_bytes": total, "reclaimable_size_bytes": reclaimable,
                        },
                        [
                            {
                                "group_id": group_id,
                                "asset_id": item["id"],
                                "role": (
                                    "protected" if item["risk_level"] == "high"
                                    else "keep_recommended" if item["id"] == keep["id"]
                                    else "duplicate_candidate"
                                ),
                                "reason": (
                                    "命中高风险规则，优先保护" if item["risk_level"] == "high"
                                    else "推荐保留版本" if item["id"] == keep["id"]
                                    else "内容 hash 与保留版本完全一致"
                                ),
                                "risk_level": item["risk_level"],
                            }
                            for item in duplicates
                        ],
                    )
                    for item in duplicates:
                        exact_by_asset[item["id"]] = (group_id, item["id"] == keep["id"])

    refreshed = repository.list_asset_rows(scan_id)
    for asset in refreshed:
        group_info = exact_by_asset.get(asset["id"])
        flags = json.loads(asset["risk_flags_json"] or "[]")
        risk = asset["risk_level"]
        if risk == "high":
            is_unique = group_info is None
            category = "likely_unique_original" if is_unique else "sensitive_protected"
            action = "protect"
            reason = "命中重要目录或敏感关键词，P0 不允许批量隔离。"
            default_selected = False
        elif group_info and not group_info[1]:
            category = "safe_to_process"
            action = "quarantine"
            reason = "与推荐保留版本的 SHA-256 完全一致，可进入可回滚隔离区。"
            default_selected = True
        elif group_info and group_info[1]:
            category = "needs_confirmation"
            action = "keep"
            reason = "这是重复组的推荐保留版本，不建议处理。"
            default_selected = False
            risk = "medium"
        elif asset["category"] in {"archive", "installer"}:
            category = "archive_suggested"
            action = "archive_suggested"
            reason = "压缩包或安装包可能占用较多空间，请人工确认是否仍需保留。"
            default_selected = False
            risk = "medium"
        else:
            category = "needs_confirmation"
            action = "review"
            reason = "没有足够证据支持自动处理，请人工确认。"
            default_selected = False
            risk = "medium"
        evidence = [
            {"type": "path", "label": "本机路径", "value": asset["abs_path"]},
            {"type": "size", "label": "文件大小", "value": str(asset["size_bytes"])},
            {"type": "category", "label": "文件类型", "value": asset["category"]},
            {"type": "source", "label": "来源判断", "value": asset["source_hint"]},
            {"type": "rule", "label": "规则版本", "value": RULE_VERSION},
        ]
        if flags:
            evidence.append({"type": "risk_keyword", "label": "风险信号", "value": ", ".join(flags)})
        if group_info:
            evidence.append({"type": "duplicate", "label": "精确重复组", "value": group_info[0]})
        repository.insert_suggestion({
            "id": new_id("sug"), "scan_session_id": scan_id, "asset_id": asset["id"],
            "dup_group_id": group_info[0] if group_info else None, "category": category,
            "risk_level": risk, "proposed_action": action, "reason": reason,
            "evidence_json": json.dumps(evidence, ensure_ascii=False), "reversible": 1,
            "default_selected": int(default_selected and risk == "low"), "status": "active",
            "created_at": utc_now().isoformat(),
        })
