from __future__ import annotations

from datetime import timedelta
import hashlib
import json
from pathlib import Path
import stat
from typing import Any

from core.app.config import Settings
from core.app.errors import DomainError
from core.app.models import (
    ErrorResponse,
    OperationExecuteRequest,
    OperationFileResult,
    OperationPlan,
    OperationPlanItem,
    OperationPreviewRequest,
    OperationReceipt,
    OperationUndoRequest,
    RiskSummaryBucket,
)
from core.db.repository import Repository, new_id, utc_now
from core.operations.quarantine import (
    QuarantineError,
    preview_cross_device,
    quarantine_file,
    restore_file,
)
from core.scanner.hashing import full_sha256


PLAN_TTL_MINUTES = 15


class OperationService:
    def __init__(self, repository: Repository, settings: Settings):
        self.repository = repository
        self.settings = settings

    def preview(self, request: OperationPreviewRequest) -> OperationPlan:
        suggestion_by_asset: dict[str, str] = {}
        asset_ids = list(dict.fromkeys(request.asset_ids or []))
        if request.suggestion_ids:
            suggestions = self.repository.get_suggestion_rows(request.suggestion_ids)
            if len(suggestions) != len(set(request.suggestion_ids)):
                raise DomainError("SUGGESTION_NOT_FOUND", "部分建议不存在", status_code=404)
            for suggestion in suggestions:
                if suggestion["asset_id"]:
                    asset_ids.append(suggestion["asset_id"])
                    suggestion_by_asset[suggestion["asset_id"]] = suggestion["id"]
        asset_ids = list(dict.fromkeys(asset_ids))
        if not asset_ids:
            raise DomainError("EMPTY_OPERATION_PLAN", "没有可预览的资产")

        rows: list[dict[str, Any]] = []
        missing: list[str] = []
        for asset_id in asset_ids:
            row = self.repository.get_asset_row(asset_id)
            if row is None:
                missing.append(asset_id)
            else:
                rows.append(row)
        if missing:
            raise DomainError(
                "ASSET_NOT_FOUND", "部分资产不存在", status_code=404, details={"asset_ids": missing}
            )
        high_risk = [row["id"] for row in rows if row["risk_level"] == "high"]
        if high_risk:
            raise DomainError(
                "HIGH_RISK_PROTECTED", "高风险资产不能进入 P0 批量操作",
                status_code=409, details={"asset_ids": high_risk},
            )
        if request.action_type == "quarantine":
            not_low = [row["id"] for row in rows if row["risk_level"] != "low"]
            if not_low:
                raise DomainError(
                    "LOW_RISK_ONLY", "P0 只允许隔离低风险精确重复候选",
                    status_code=409, details={"asset_ids": not_low},
                )

        warnings: list[str] = []
        public_items: list[OperationPlanItem] = []
        internal_items: list[dict[str, Any]] = []
        for row in rows:
            item_warnings: list[str] = []
            path = Path(row["abs_path"])
            if row["status"] != "active":
                item_warnings.append("资产当前不是 active 状态")
            try:
                info = path.stat(follow_symlinks=False)
                if path.is_symlink() or not stat.S_ISREG(info.st_mode):
                    item_warnings.append("源路径不是普通文件")
                if request.action_type == "quarantine" and preview_cross_device(
                    path, self.settings.resolved_quarantine_path
                ):
                    item_warnings.append("源文件与隔离区跨磁盘，P0 执行时会拒绝")
            except OSError:
                item_warnings.append("预览时无法读取源文件")
            warnings.extend(f"{row['id']}：{warning}" for warning in item_warnings)
            public_items.append(OperationPlanItem(
                asset_id=row["id"], suggestion_id=suggestion_by_asset.get(row["id"]),
                display_path=row["abs_path"], size_bytes=row["size_bytes"],
                risk_level=row["risk_level"], reversible=True, warnings=item_warnings,
            ))

        created_at = utc_now()
        expires_at = created_at + timedelta(minutes=PLAN_TTL_MINUTES)
        canonical = {
            "action_type": request.action_type,
            "target_policy": request.target_policy,
            "items": [
                {
                    "asset_id": row["id"], "path": row["abs_path"], "size": row["size_bytes"],
                    "modified_ns": row["modified_ns"], "file_hash": row["file_hash"],
                    "device_id": row["device_id"], "risk_level": row["risk_level"],
                }
                for row in sorted(rows, key=lambda value: value["id"])
            ],
            "warnings": sorted(warnings),
        }
        version = hashlib.sha256(
            json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        risk_counts: dict[str, list[int]] = {}
        for row in rows:
            bucket = risk_counts.setdefault(row["risk_level"], [0, 0])
            bucket[0] += 1
            bucket[1] += int(row["size_bytes"])
        plan = OperationPlan(
            id=new_id("plan"), action_type=request.action_type, status="previewed", reversible=True,
            summary={
                "file_count": len(rows),
                "total_size_bytes": sum(int(row["size_bytes"]) for row in rows),
                "target_policy": request.target_policy,
            },
            risk_summary=[
                RiskSummaryBucket(risk_level=key, file_count=value[0], size_bytes=value[1])
                for key, value in sorted(risk_counts.items())
            ],
            items=public_items, warnings=warnings, version=version,
            created_at=created_at, expires_at=expires_at,
        )
        for row, public in zip(rows, public_items, strict=True):
            internal_items.append({
                "plan_id": plan.id, "asset_id": row["id"],
                "suggestion_id": public.suggestion_id, "display_path": row["abs_path"],
                "size_bytes": row["size_bytes"], "modified_ns": row["modified_ns"],
                "file_hash": row["file_hash"], "device_id": row["device_id"],
                "risk_level": row["risk_level"],
                "warnings_json": json.dumps(public.warnings, ensure_ascii=False),
            })
        self.repository.save_plan(plan, internal_items)
        return plan

    def execute(self, request: OperationExecuteRequest) -> OperationReceipt:
        if request.idempotency_key:
            existing = self.repository.get_receipt_by_idempotency_key(request.idempotency_key)
            if existing:
                return existing
        loaded = self.repository.get_plan_internal(request.operation_plan_id)
        if loaded is None:
            raise DomainError("OPERATION_PLAN_NOT_FOUND", "操作预览不存在", status_code=404)
        plan, items = loaded
        if plan.status != "previewed":
            raise DomainError("OPERATION_PLAN_NOT_EXECUTABLE", "操作预览当前不可执行", status_code=409)
        if plan.expires_at <= utc_now():
            self.repository.set_plan_status(plan.id, "expired")
            raise DomainError("OPERATION_PLAN_EXPIRED", "操作预览已过期，请重新预览", status_code=409)
        if request.client_seen_plan_version != plan.version:
            raise DomainError("OPERATION_PLAN_VERSION_MISMATCH", "预览版本已变化，请重新确认", status_code=409)

        operation_id = new_id("op")
        started = utc_now()
        self.repository.create_receipt({
            "id": operation_id, "operation_plan_id": plan.id, "action_type": plan.action_type,
            "status": "failed", "file_count": len(items),
            "total_size_bytes": sum(int(item["size_bytes"]) for item in items),
            "started_at": started.isoformat(), "finished_at": None,
            "rule_version": "p0-rules-v1", "provider_version": None,
            "idempotency_key": request.idempotency_key,
        })
        succeeded = 0
        for item in items:
            try:
                current = self._validate_snapshot(item, plan.action_type)
                if plan.action_type == "mark_ignored":
                    self.repository.set_asset_status(item["asset_id"], "ignored")
                    result = OperationFileResult(
                        asset_id=item["asset_id"], status="succeeded", original_path=item["display_path"]
                    )
                else:
                    source = Path(item["display_path"])
                    destination = quarantine_file(
                        source=source, quarantine_root=self.settings.resolved_quarantine_path,
                        operation_id=operation_id, asset_id=item["asset_id"],
                    )
                    quarantine_id = new_id("quarantine")
                    self.repository.insert_quarantine_item({
                        "id": quarantine_id, "operation_id": operation_id,
                        "asset_id": item["asset_id"], "original_path": item["display_path"],
                        "quarantine_path": str(destination),
                        "original_mtime": current["modified_at"],
                        "original_mtime_ns": current["modified_ns"],
                        "original_size_bytes": current["size_bytes"],
                        "file_hash": current["file_hash"], "device_id": current["device_id"],
                        "status": "quarantined", "error_message": None,
                    })
                    self.repository.set_asset_status(item["asset_id"], "quarantined")
                    result = OperationFileResult(
                        asset_id=item["asset_id"], status="succeeded",
                        original_path=item["display_path"], quarantine_item_id=quarantine_id,
                    )
                succeeded += 1
            except (DomainError, QuarantineError, OSError) as exc:
                code = exc.code if isinstance(exc, (DomainError, QuarantineError)) else type(exc).__name__.upper()
                result = OperationFileResult(
                    asset_id=item["asset_id"], status="failed", original_path=item["display_path"],
                    error=ErrorResponse(code=code, message=str(exc) or "文件操作失败"),
                )
            self.repository.add_operation_result(operation_id, "execute", result)
        status_value = "succeeded" if succeeded == len(items) else "partial" if succeeded else "failed"
        self.repository.update_receipt(operation_id, status=status_value, finished_at=utc_now())
        self.repository.set_plan_status(plan.id, "executed")
        receipt = self.repository.get_receipt(operation_id)
        if receipt is None:
            raise DomainError("RECEIPT_MISSING", "操作收据写入失败", status_code=500)
        return receipt

    def undo(self, operation_id: str, _request: OperationUndoRequest) -> OperationReceipt:
        receipt = self.repository.get_receipt(operation_id)
        if receipt is None:
            raise DomainError("OPERATION_NOT_FOUND", "操作收据不存在", status_code=404)
        if receipt.status in {"undone", "undo_partial"}:
            raise DomainError("OPERATION_ALREADY_UNDONE", "操作已经撤销", status_code=409)
        loaded = self.repository.get_plan_internal(receipt.operation_plan_id)
        if loaded is None:
            raise DomainError("OPERATION_PLAN_NOT_FOUND", "操作预览不存在", status_code=409)
        plan, plan_items = loaded
        succeeded = 0
        if receipt.action_type == "mark_ignored":
            for item in plan_items:
                self.repository.set_asset_status(item["asset_id"], "active")
                self.repository.add_operation_result(
                    operation_id, "undo", OperationFileResult(
                        asset_id=item["asset_id"], status="succeeded", original_path=item["display_path"]
                    )
                )
                succeeded += 1
            total = len(plan_items)
        else:
            quarantine_rows = self.repository.get_quarantine_rows(operation_id)
            total = len(quarantine_rows)
            if total == 0:
                raise DomainError("QUARANTINE_ITEMS_MISSING", "收据没有对应隔离记录", status_code=409)
            for item in quarantine_rows:
                try:
                    restore_file(
                        quarantined=Path(item["quarantine_path"]),
                        original=Path(item["original_path"]), expected_device=item["device_id"],
                    )
                    self.repository.update_quarantine_status(item["id"], "restored")
                    self.repository.set_asset_status(item["asset_id"], "active")
                    result = OperationFileResult(
                        asset_id=item["asset_id"], status="succeeded",
                        original_path=item["original_path"], quarantine_item_id=item["id"],
                    )
                    succeeded += 1
                except (QuarantineError, OSError) as exc:
                    code = exc.code if isinstance(exc, QuarantineError) else type(exc).__name__.upper()
                    self.repository.update_quarantine_status(item["id"], "restore_failed", str(exc))
                    result = OperationFileResult(
                        asset_id=item["asset_id"], status="failed",
                        original_path=item["original_path"], quarantine_item_id=item["id"],
                        error=ErrorResponse(code=code, message=str(exc) or "撤销失败"),
                    )
                self.repository.add_operation_result(operation_id, "undo", result)
        status_value = "undone" if succeeded == total else "undo_partial"
        self.repository.update_receipt(operation_id, status=status_value, finished_at=utc_now())
        updated = self.repository.get_receipt(operation_id)
        if updated is None:
            raise DomainError("RECEIPT_MISSING", "操作收据更新失败", status_code=500)
        return updated

    def _validate_snapshot(self, item: dict[str, Any], action_type: str) -> dict[str, Any]:
        current = self.repository.get_asset_row(item["asset_id"])
        if current is None:
            raise DomainError("ASSET_NOT_FOUND", "资产不存在")
        if current["status"] != "active":
            raise DomainError("ASSET_STATE_CHANGED", "资产状态已变化")
        if current["risk_level"] == "high":
            raise DomainError("HIGH_RISK_PROTECTED", "高风险资产受保护")
        if action_type == "quarantine" and current["risk_level"] != "low":
            raise DomainError("LOW_RISK_ONLY", "P0 只允许隔离低风险资产")
        path = Path(item["display_path"])
        info = path.stat(follow_symlinks=False)
        if path.is_symlink() or not stat.S_ISREG(info.st_mode):
            raise DomainError("SOURCE_NOT_REGULAR", "源路径不再是普通文件")
        if int(info.st_size) != int(item["size_bytes"]) or int(info.st_mtime_ns) != int(item["modified_ns"]):
            raise DomainError("ASSET_SNAPSHOT_CHANGED", "文件在预览后发生变化")
        if item["file_hash"]:
            digest = full_sha256(path)
            if digest != item["file_hash"]:
                raise DomainError("ASSET_HASH_CHANGED", "文件内容在预览后发生变化")
        return current
