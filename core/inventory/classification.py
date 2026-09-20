from __future__ import annotations

from core.inventory.models import ObjectType, RuleHintV1, ScanFactV1


RULES_VERSION = "inventory-rules-v1"


def classify_fact(fact: ScanFactV1) -> ObjectType:
    path = fact.relative_path.casefold()
    name = fact.name.casefold()
    if fact.file_type == "directory":
        if name.endswith(".app") or "/applications/" in f"/{path}/":
            return "application"
        if any(marker in path for marker in ("steamapps", "game-library", "游戏库")):
            return "game_library"
        if any(marker in path for marker in ("node_modules", ".cache", "/cache", "缓存")):
            return "cache_group"
        if any(marker in path for marker in ("package-store", "pip-cache", "npm-cache")):
            return "package_manager_store"
        if any(marker in path for marker in ("local-model", "models", "模型")):
            return "local_model"
        if any(marker in path for marker in ("project", "项目", "workspace", "src")):
            return "project"
        return "directory"
    if fact.file_type != "file":
        return "file"
    if fact.extension in {".zip", ".rar", ".7z", ".tar", ".gz", ".tgz"}:
        return "archive"
    if fact.extension in {".dmg", ".pkg", ".exe", ".msi", ".appinstaller", ".iso"}:
        return "installer"
    return "file"


def rule_hints_for(object_type: ObjectType) -> list[RuleHintV1]:
    if object_type in {"cache_group", "package_manager_store"}:
        return [
            RuleHintV1(
                rule_id="review-rebuildable-storage",
                rules_version=RULES_VERSION,
                message="可能可重建，但本报告未核验可腾出空间；建议先确认来源与恢复方式。",
                priority="建议先看",
            )
        ]
    if object_type in {"installer", "archive"}:
        return [
            RuleHintV1(
                rule_id="review-installer-archive",
                rules_version=RULES_VERSION,
                message="安装包或归档文件可能值得人工核实，尚未核验重复或可处理性。",
                priority="有空再看",
            )
        ]
    if object_type in {"project", "local_model", "game_library", "application"}:
        return [
            RuleHintV1(
                rule_id="protect-rebuild-context",
                rules_version=RULES_VERSION,
                message="先确认唯一性、重建成本和当前用途；本报告不授权处理。",
                priority="留意即可",
            )
        ]
    return []
