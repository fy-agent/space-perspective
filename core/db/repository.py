from __future__ import annotations

from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any, Iterable
from uuid import uuid4

from core.app.models import (
    Asset,
    AssetDetail,
    AssetList,
    AssetMetadata,
    DuplicateGroup,
    DuplicateGroupList,
    DuplicateMember,
    ErrorResponse,
    FileIntelOverview,
    OperationFileResult,
    OperationPlan,
    OperationReceipt,
    OperationReceiptList,
    OverviewBucket,
    PageInfo,
    QuarantineItem,
    QuarantineItemList,
    RiskSummaryBucket,
    ScanEvent,
    ScanRequest,
    ScanSession,
    Suggestion,
    SuggestionEvidence,
    SuggestionList,
)
from core.db.connection import connect


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex}"


def _dump(value: Any) -> str:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        default=lambda item: (
            item.model_dump(mode="json") if hasattr(item, "model_dump") else item.isoformat()
        ),
    )


def _load(value: str | None, default: Any) -> Any:
    return json.loads(value) if value else default


def _canonical_dump(value: Any) -> str:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


class Repository:
    def __init__(self, database_path: Path):
        self.database_path = database_path

    def create_scan(self, request: ScanRequest) -> ScanSession:
        session = ScanSession(
            id=new_id("scan"),
            status="pending",
            requested_paths=request.paths,
            started_at=utc_now(),
            files_seen=0,
            files_indexed=0,
            files_skipped=0,
            bytes_seen=0,
        )
        with closing(connect(self.database_path)) as connection:
            connection.execute(
                """
                INSERT INTO scan_sessions(
                    id, requested_paths_json, options_json, status, started_at,
                    files_seen, files_indexed, files_skipped, bytes_seen, error_summary_json
                ) VALUES (?, ?, ?, ?, ?, 0, 0, 0, 0, '[]')
                """,
                (
                    session.id,
                    _dump(request.paths),
                    _dump(request.options),
                    session.status,
                    session.started_at.isoformat(),
                ),
            )
            connection.commit()
        return session

    def get_scan(self, scan_id: str) -> ScanSession | None:
        with closing(connect(self.database_path)) as connection:
            row = connection.execute("SELECT * FROM scan_sessions WHERE id = ?", (scan_id,)).fetchone()
        return self._scan_from_row(row) if row else None

    def latest_scan_id(self) -> str | None:
        with closing(connect(self.database_path)) as connection:
            row = connection.execute(
                "SELECT id FROM scan_sessions ORDER BY started_at DESC LIMIT 1"
            ).fetchone()
        return str(row["id"]) if row else None

    def update_scan(
        self,
        scan_id: str,
        *,
        status: str,
        current_path: str | None,
        files_seen: int,
        files_indexed: int,
        files_skipped: int,
        bytes_seen: int,
        error_summary: list[dict[str, Any]],
        finished_at: datetime | None = None,
    ) -> None:
        with closing(connect(self.database_path)) as connection:
            connection.execute(
                """
                UPDATE scan_sessions
                SET status = ?, current_path = ?, files_seen = ?, files_indexed = ?,
                    files_skipped = ?, bytes_seen = ?, error_summary_json = ?, finished_at = ?
                WHERE id = ?
                """,
                (
                    status,
                    current_path,
                    files_seen,
                    files_indexed,
                    files_skipped,
                    bytes_seen,
                    _dump(error_summary),
                    finished_at.isoformat() if finished_at else None,
                    scan_id,
                ),
            )
            connection.commit()

    def request_scan_cancel(self, scan_id: str) -> bool:
        with closing(connect(self.database_path)) as connection:
            cursor = connection.execute(
                "UPDATE scan_sessions SET cancel_requested = 1 WHERE id = ?", (scan_id,)
            )
            connection.commit()
        return cursor.rowcount > 0

    def is_scan_cancel_requested(self, scan_id: str) -> bool:
        with closing(connect(self.database_path)) as connection:
            row = connection.execute(
                "SELECT cancel_requested FROM scan_sessions WHERE id = ?", (scan_id,)
            ).fetchone()
        return bool(row and row["cancel_requested"])

    def add_scan_event(self, event: ScanEvent) -> None:
        with closing(connect(self.database_path)) as connection:
            connection.execute(
                "INSERT INTO scan_events(event_id, scan_session_id, event_type, occurred_at, payload_json) VALUES (?, ?, ?, ?, ?)",
                (
                    event.event_id,
                    event.scan_session_id,
                    event.type,
                    event.occurred_at.isoformat(),
                    _dump(event),
                ),
            )
            connection.commit()

    def list_scan_events(self, scan_id: str, last_event_id: str | None = None) -> list[ScanEvent]:
        with closing(connect(self.database_path)) as connection:
            after_id = 0
            if last_event_id:
                previous = connection.execute(
                    "SELECT id FROM scan_events WHERE scan_session_id = ? AND event_id = ?",
                    (scan_id, last_event_id),
                ).fetchone()
                if previous:
                    after_id = int(previous["id"])
            rows = connection.execute(
                "SELECT payload_json FROM scan_events WHERE scan_session_id = ? AND id > ? ORDER BY id",
                (scan_id, after_id),
            ).fetchall()
        return [ScanEvent.model_validate(_load(row["payload_json"], {})) for row in rows]

    def insert_asset(self, asset: dict[str, Any], metadata: Iterable[dict[str, Any]]) -> None:
        with closing(connect(self.database_path)) as connection:
            connection.execute(
                """
                INSERT INTO assets(
                    id, scan_session_id, abs_path, path_hash, file_hash, partial_hash,
                    hash_status, size_bytes, ext, mime, category, source_hint,
                    created_at, modified_at, modified_ns, accessed_at, device_id,
                    status, risk_level, risk_flags_json
                ) VALUES (
                    :id, :scan_session_id, :abs_path, :path_hash, :file_hash, :partial_hash,
                    :hash_status, :size_bytes, :ext, :mime, :category, :source_hint,
                    :created_at, :modified_at, :modified_ns, :accessed_at, :device_id,
                    :status, :risk_level, :risk_flags_json
                )
                ON CONFLICT(scan_session_id, abs_path) DO UPDATE SET
                    size_bytes=excluded.size_bytes, ext=excluded.ext, mime=excluded.mime,
                    category=excluded.category, source_hint=excluded.source_hint,
                    created_at=excluded.created_at, modified_at=excluded.modified_at,
                    modified_ns=excluded.modified_ns, accessed_at=excluded.accessed_at,
                    device_id=excluded.device_id, risk_level=excluded.risk_level,
                    risk_flags_json=excluded.risk_flags_json
                """,
                asset,
            )
            for item in metadata:
                connection.execute(
                    """
                    INSERT INTO asset_metadata(asset_id, key, value, raw_json)
                    VALUES (:asset_id, :key, :value, :raw_json)
                    ON CONFLICT(asset_id, key) DO UPDATE SET value=excluded.value, raw_json=excluded.raw_json
                    """,
                    item,
                )
            connection.commit()

    def list_asset_rows(self, scan_id: str, *, status: str | None = "active") -> list[dict[str, Any]]:
        sql = "SELECT * FROM assets WHERE scan_session_id = ?"
        parameters: list[Any] = [scan_id]
        if status:
            sql += " AND status = ?"
            parameters.append(status)
        sql += " ORDER BY abs_path"
        with closing(connect(self.database_path)) as connection:
            return [dict(row) for row in connection.execute(sql, parameters).fetchall()]

    def get_asset_row(self, asset_id: str) -> dict[str, Any] | None:
        with closing(connect(self.database_path)) as connection:
            row = connection.execute("SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone()
        return dict(row) if row else None

    def update_asset_hash(
        self, asset_id: str, *, partial_hash: str | None, file_hash: str | None, hash_status: str
    ) -> None:
        with closing(connect(self.database_path)) as connection:
            connection.execute(
                "UPDATE assets SET partial_hash = ?, file_hash = ?, hash_status = ? WHERE id = ?",
                (partial_hash, file_hash, hash_status, asset_id),
            )
            connection.commit()

    def update_asset_risk(self, asset_id: str, risk_level: str, risk_flags: list[str]) -> None:
        with closing(connect(self.database_path)) as connection:
            connection.execute(
                "UPDATE assets SET risk_level = ?, risk_flags_json = ? WHERE id = ?",
                (risk_level, _dump(risk_flags), asset_id),
            )
            connection.commit()

    def set_asset_status(self, asset_id: str, status: str) -> None:
        with closing(connect(self.database_path)) as connection:
            connection.execute("UPDATE assets SET status = ? WHERE id = ?", (status, asset_id))
            connection.commit()

    def list_assets(
        self,
        *,
        scan_id: str | None,
        category: str | None,
        source_hint: str | None,
        status: str | None,
        min_size_bytes: int | None,
        page: int,
        page_size: int,
    ) -> AssetList:
        clauses: list[str] = []
        parameters: list[Any] = []
        for column, value in (
            ("scan_session_id", scan_id), ("category", category),
            ("source_hint", source_hint), ("status", status),
        ):
            if value is not None:
                clauses.append(f"{column} = ?")
                parameters.append(value)
        if min_size_bytes is not None:
            clauses.append("size_bytes >= ?")
            parameters.append(min_size_bytes)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with closing(connect(self.database_path)) as connection:
            total = int(connection.execute(
                f"SELECT COUNT(*) FROM assets {where}", parameters
            ).fetchone()[0])
            rows = connection.execute(
                f"SELECT * FROM assets {where} ORDER BY size_bytes DESC, id LIMIT ? OFFSET ?",
                (*parameters, page_size, (page - 1) * page_size),
            ).fetchall()
        return AssetList(
            items=[self._asset_from_row(row) for row in rows],
            page=PageInfo(page=page, page_size=page_size, total=total),
        )

    def get_asset_detail(self, asset_id: str) -> AssetDetail | None:
        with closing(connect(self.database_path)) as connection:
            row = connection.execute("SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone()
            metadata_rows = connection.execute(
                "SELECT asset_id, key, value, raw_json FROM asset_metadata WHERE asset_id = ? ORDER BY key",
                (asset_id,),
            ).fetchall()
        if row is None:
            return None
        metadata = [
            AssetMetadata(
                asset_id=item["asset_id"], key=item["key"], value=item["value"],
                raw_json=_load(item["raw_json"], None),
            )
            for item in metadata_rows
        ]
        return AssetDetail(asset=self._asset_from_row(row), metadata=metadata)

    def clear_intelligence(self, scan_id: str) -> None:
        with closing(connect(self.database_path)) as connection:
            connection.execute("DELETE FROM suggestions WHERE scan_session_id = ?", (scan_id,))
            connection.execute("DELETE FROM duplicate_groups WHERE scan_session_id = ?", (scan_id,))
            connection.commit()

    def insert_duplicate_group(
        self, group: dict[str, Any], members: list[dict[str, Any]]
    ) -> None:
        with closing(connect(self.database_path)) as connection:
            connection.execute(
                """
                INSERT INTO duplicate_groups(
                    id, scan_session_id, kind, file_hash, keep_asset_id, reason,
                    total_size_bytes, reclaimable_size_bytes
                ) VALUES (:id, :scan_session_id, 'exact', :file_hash, :keep_asset_id,
                    :reason, :total_size_bytes, :reclaimable_size_bytes)
                """,
                group,
            )
            connection.executemany(
                """
                INSERT INTO duplicate_members(group_id, asset_id, role, similarity, reason, risk_level)
                VALUES (:group_id, :asset_id, :role, 1.0, :reason, :risk_level)
                """,
                members,
            )
            connection.commit()

    def insert_suggestion(self, item: dict[str, Any]) -> None:
        with closing(connect(self.database_path)) as connection:
            connection.execute(
                """
                INSERT INTO suggestions(
                    id, scan_session_id, asset_id, dup_group_id, category, risk_level,
                    proposed_action, reason, evidence_json, reversible,
                    default_selected, status, created_at
                ) VALUES (
                    :id, :scan_session_id, :asset_id, :dup_group_id, :category, :risk_level,
                    :proposed_action, :reason, :evidence_json, :reversible,
                    :default_selected, :status, :created_at
                )
                """,
                item,
            )
            connection.commit()

    def get_overview(self, scan_id: str) -> FileIntelOverview:
        with closing(connect(self.database_path)) as connection:
            totals = connection.execute(
                "SELECT COUNT(*), COALESCE(SUM(size_bytes), 0) FROM assets WHERE scan_session_id = ? AND status = 'active'",
                (scan_id,),
            ).fetchone()
            categories = connection.execute(
                "SELECT category AS key, COUNT(*) AS file_count, SUM(size_bytes) AS size_bytes FROM assets WHERE scan_session_id = ? AND status = 'active' GROUP BY category ORDER BY size_bytes DESC",
                (scan_id,),
            ).fetchall()
            sources = connection.execute(
                "SELECT source_hint AS key, COUNT(*) AS file_count, SUM(size_bytes) AS size_bytes FROM assets WHERE scan_session_id = ? AND status = 'active' GROUP BY source_hint ORDER BY size_bytes DESC",
                (scan_id,),
            ).fetchall()
            directories = connection.execute(
                "SELECT abs_path, size_bytes FROM assets WHERE scan_session_id = ? AND status = 'active'",
                (scan_id,),
            ).fetchall()
            top = connection.execute(
                "SELECT * FROM assets WHERE scan_session_id = ? AND status = 'active' ORDER BY size_bytes DESC LIMIT 10",
                (scan_id,),
            ).fetchall()
            risks = connection.execute(
                "SELECT risk_level, COUNT(*) AS file_count, SUM(size_bytes) AS size_bytes FROM assets WHERE scan_session_id = ? AND status = 'active' GROUP BY risk_level ORDER BY risk_level",
                (scan_id,),
            ).fetchall()
        directory_totals: dict[str, list[int]] = {}
        for row in directories:
            key = str(Path(row["abs_path"]).parent)
            bucket = directory_totals.setdefault(key, [0, 0])
            bucket[0] += 1
            bucket[1] += int(row["size_bytes"])
        by_directory = [
            OverviewBucket(key=key, file_count=value[0], size_bytes=value[1])
            for key, value in sorted(directory_totals.items(), key=lambda pair: pair[1][1], reverse=True)[:20]
        ]
        return FileIntelOverview(
            scan_session_id=scan_id,
            total_files=int(totals[0]),
            total_size_bytes=int(totals[1]),
            by_category=[OverviewBucket(**dict(row)) for row in categories],
            by_source=[OverviewBucket(**dict(row)) for row in sources],
            by_directory=by_directory,
            top_large_files=[self._asset_from_row(row) for row in top],
            risk_summary=[RiskSummaryBucket(**dict(row)) for row in risks],
            generated_at=utc_now(),
        )

    def list_duplicate_groups(
        self, scan_id: str | None, min_reclaimable: int, page: int, page_size: int
    ) -> DuplicateGroupList:
        clauses = ["a.status = 'active'"]
        parameters: list[Any] = []
        if scan_id:
            clauses.append("g.scan_session_id = ?")
            parameters.append(scan_id)
        where = " AND ".join(clauses)
        active_groups = f"""
            SELECT g.*, COUNT(a.id) AS active_member_count,
                   SUM(a.size_bytes) AS active_total_size_bytes,
                   MAX(CASE WHEN a.id = g.keep_asset_id THEN a.size_bytes ELSE 0 END) AS active_keep_size
            FROM duplicate_groups g
            JOIN duplicate_members dm ON dm.group_id = g.id
            JOIN assets a ON a.id = dm.asset_id
            WHERE {where}
            GROUP BY g.id
            HAVING active_member_count >= 2
               AND active_keep_size > 0
               AND active_total_size_bytes - active_keep_size >= ?
        """
        with closing(connect(self.database_path)) as connection:
            total = int(connection.execute(
                f"SELECT COUNT(*) FROM ({active_groups})", (*parameters, min_reclaimable)
            ).fetchone()[0])
            groups = connection.execute(
                f"SELECT * FROM ({active_groups}) ORDER BY active_total_size_bytes - active_keep_size DESC LIMIT ? OFFSET ?",
                (*parameters, min_reclaimable, page_size, (page - 1) * page_size),
            ).fetchall()
            items: list[DuplicateGroup] = []
            for group in groups:
                members = connection.execute(
                    """
                    SELECT dm.* FROM duplicate_members dm
                    JOIN assets a ON a.id = dm.asset_id
                    WHERE dm.group_id = ? AND a.status = 'active'
                    ORDER BY dm.role DESC, dm.asset_id
                    """,
                    (group["id"],),
                ).fetchall()
                items.append(DuplicateGroup(
                    id=group["id"], file_hash=group["file_hash"], member_count=len(members),
                    total_size_bytes=group["active_total_size_bytes"],
                    reclaimable_size_bytes=group["active_total_size_bytes"] - group["active_keep_size"],
                    keep_asset_id=group["keep_asset_id"], reason=group["reason"],
                    members=[DuplicateMember(
                        asset_id=row["asset_id"], role=row["role"], similarity=row["similarity"],
                        reason=row["reason"], risk_level=row["risk_level"],
                    ) for row in members],
                ))
        return DuplicateGroupList(items=items, page=PageInfo(page=page, page_size=page_size, total=total))

    def list_suggestions(
        self, *, scan_id: str | None, category: str | None, risk_level: str | None,
        default_selected: bool | None, page: int, page_size: int,
    ) -> SuggestionList:
        clauses = [
            "s.status = 'active'",
            "(s.asset_id IS NULL OR EXISTS (SELECT 1 FROM assets a WHERE a.id = s.asset_id AND a.status = 'active'))",
        ]
        parameters: list[Any] = []
        for column, value in (("scan_session_id", scan_id), ("category", category), ("risk_level", risk_level)):
            if value is not None:
                clauses.append(f"s.{column} = ?")
                parameters.append(value)
        if default_selected is not None:
            clauses.append("s.default_selected = ?")
            parameters.append(int(default_selected))
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with closing(connect(self.database_path)) as connection:
            total = int(connection.execute(
                f"SELECT COUNT(*) FROM suggestions s {where}", parameters
            ).fetchone()[0])
            rows = connection.execute(
                f"SELECT s.* FROM suggestions s {where} ORDER BY s.default_selected DESC, s.risk_level, s.created_at LIMIT ? OFFSET ?",
                (*parameters, page_size, (page - 1) * page_size),
            ).fetchall()
        return SuggestionList(
            items=[self._suggestion_from_row(row) for row in rows],
            page=PageInfo(page=page, page_size=page_size, total=total),
        )

    def get_suggestion_rows(self, ids: list[str]) -> list[dict[str, Any]]:
        if not ids:
            return []
        placeholders = ",".join("?" for _ in ids)
        with closing(connect(self.database_path)) as connection:
            rows = connection.execute(
                f"""
                SELECT s.* FROM suggestions s
                WHERE s.id IN ({placeholders})
                  AND s.status = 'active'
                  AND (s.asset_id IS NULL OR EXISTS (
                      SELECT 1 FROM assets a WHERE a.id = s.asset_id AND a.status = 'active'
                  ))
                """,
                ids,
            ).fetchall()
        return [dict(row) for row in rows]

    def save_plan(self, plan: OperationPlan, internal_items: list[dict[str, Any]]) -> None:
        with closing(connect(self.database_path)) as connection:
            connection.execute(
                """
                INSERT INTO operation_plans(
                    id, action_type, target_policy, status, reversible, summary_json,
                    risk_summary_json, warnings_json, version, created_at, expires_at
                ) VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?)
                """,
                (
                    plan.id, plan.action_type, plan.summary.target_policy, plan.status,
                    _dump(plan.summary), _dump(plan.risk_summary), _dump(plan.warnings),
                    plan.version, plan.created_at.isoformat(), plan.expires_at.isoformat(),
                ),
            )
            connection.executemany(
                """
                INSERT INTO operation_plan_items(
                    plan_id, asset_id, suggestion_id, display_path, size_bytes,
                    modified_ns, file_hash, device_id, risk_level, reversible, warnings_json
                ) VALUES (
                    :plan_id, :asset_id, :suggestion_id, :display_path, :size_bytes,
                    :modified_ns, :file_hash, :device_id, :risk_level, 1, :warnings_json
                )
                """,
                internal_items,
            )
            connection.commit()

    def get_plan_internal(self, plan_id: str) -> tuple[OperationPlan, list[dict[str, Any]]] | None:
        with closing(connect(self.database_path)) as connection:
            row = connection.execute("SELECT * FROM operation_plans WHERE id = ?", (plan_id,)).fetchone()
            items = connection.execute(
                "SELECT * FROM operation_plan_items WHERE plan_id = ? ORDER BY asset_id", (plan_id,)
            ).fetchall()
        if row is None:
            return None
        public_items = [
            {
                "asset_id": item["asset_id"], "suggestion_id": item["suggestion_id"],
                "display_path": item["display_path"], "size_bytes": item["size_bytes"],
                "risk_level": item["risk_level"], "reversible": bool(item["reversible"]),
                "warnings": _load(item["warnings_json"], []),
            }
            for item in items
        ]
        plan = OperationPlan(
            id=row["id"], action_type=row["action_type"], status=row["status"], reversible=True,
            summary=_load(row["summary_json"], {}), risk_summary=_load(row["risk_summary_json"], []),
            items=public_items, warnings=_load(row["warnings_json"], []), version=row["version"],
            created_at=row["created_at"], expires_at=row["expires_at"],
        )
        return plan, [dict(item) for item in items]

    def set_plan_status(self, plan_id: str, status: str) -> None:
        with closing(connect(self.database_path)) as connection:
            connection.execute("UPDATE operation_plans SET status = ? WHERE id = ?", (status, plan_id))
            connection.commit()

    def create_receipt(self, values: dict[str, Any]) -> None:
        with closing(connect(self.database_path)) as connection:
            connection.execute(
                """
                INSERT INTO operation_receipts(
                    id, operation_plan_id, action_type, status, reversible,
                    file_count, total_size_bytes, started_at, finished_at,
                    affects_cloud_sync, rule_version, provider_version, idempotency_key
                ) VALUES (
                    :id, :operation_plan_id, :action_type, :status, 1,
                    :file_count, :total_size_bytes, :started_at, :finished_at,
                    0, :rule_version, :provider_version, :idempotency_key
                )
                """,
                values,
            )
            connection.commit()

    def update_receipt(self, operation_id: str, *, status: str, finished_at: datetime) -> None:
        with closing(connect(self.database_path)) as connection:
            connection.execute(
                "UPDATE operation_receipts SET status = ?, finished_at = ? WHERE id = ?",
                (status, finished_at.isoformat(), operation_id),
            )
            connection.commit()

    def add_operation_result(
        self, operation_id: str, phase: str, result: OperationFileResult
    ) -> None:
        with closing(connect(self.database_path)) as connection:
            connection.execute(
                """
                INSERT INTO operation_file_results(
                    operation_id, phase, asset_id, status, original_path,
                    quarantine_item_id, error_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    operation_id, phase, result.asset_id, result.status, result.original_path,
                    result.quarantine_item_id, _dump(result.error) if result.error else None,
                ),
            )
            connection.commit()

    def get_receipt(self, operation_id: str) -> OperationReceipt | None:
        with closing(connect(self.database_path)) as connection:
            row = connection.execute(
                "SELECT * FROM operation_receipts WHERE id = ?", (operation_id,)
            ).fetchone()
            if row is None:
                return None
            phase = "undo" if row["status"] in {"undone", "undo_partial"} else "execute"
            results = connection.execute(
                "SELECT * FROM operation_file_results WHERE operation_id = ? AND phase = ? ORDER BY id",
                (operation_id, phase),
            ).fetchall()
        return self._receipt_from_row(row, results)

    def get_receipt_by_idempotency_key(self, key: str) -> OperationReceipt | None:
        with closing(connect(self.database_path)) as connection:
            row = connection.execute(
                "SELECT id FROM operation_receipts WHERE idempotency_key = ?", (key,)
            ).fetchone()
        return self.get_receipt(row["id"]) if row else None

    def list_receipts(self, status: str | None, page: int, page_size: int) -> OperationReceiptList:
        where = "WHERE status = ?" if status else ""
        parameters: list[Any] = [status] if status else []
        with closing(connect(self.database_path)) as connection:
            total = int(connection.execute(
                f"SELECT COUNT(*) FROM operation_receipts {where}", parameters
            ).fetchone()[0])
            rows = connection.execute(
                f"SELECT id FROM operation_receipts {where} ORDER BY started_at DESC LIMIT ? OFFSET ?",
                (*parameters, page_size, (page - 1) * page_size),
            ).fetchall()
        items = [receipt for row in rows if (receipt := self.get_receipt(row["id"])) is not None]
        return OperationReceiptList(items=items, page=PageInfo(page=page, page_size=page_size, total=total))

    def insert_quarantine_item(self, values: dict[str, Any]) -> None:
        with closing(connect(self.database_path)) as connection:
            connection.execute(
                """
                INSERT INTO quarantine_items(
                    id, operation_id, asset_id, original_path, quarantine_path,
                    original_mtime, original_mtime_ns, original_size_bytes,
                    file_hash, device_id, status, error_message
                ) VALUES (
                    :id, :operation_id, :asset_id, :original_path, :quarantine_path,
                    :original_mtime, :original_mtime_ns, :original_size_bytes,
                    :file_hash, :device_id, :status, :error_message
                )
                """,
                values,
            )
            connection.commit()

    def update_quarantine_status(self, item_id: str, status: str, error_message: str | None = None) -> None:
        with closing(connect(self.database_path)) as connection:
            connection.execute(
                "UPDATE quarantine_items SET status = ?, error_message = ? WHERE id = ?",
                (status, error_message, item_id),
            )
            connection.commit()

    def get_quarantine_rows(self, operation_id: str) -> list[dict[str, Any]]:
        with closing(connect(self.database_path)) as connection:
            rows = connection.execute(
                "SELECT * FROM quarantine_items WHERE operation_id = ? ORDER BY id", (operation_id,)
            ).fetchall()
        return [dict(row) for row in rows]

    def list_quarantine(
        self, operation_id: str | None, status: str | None, page: int, page_size: int
    ) -> QuarantineItemList:
        clauses: list[str] = []
        parameters: list[Any] = []
        for column, value in (("operation_id", operation_id), ("status", status)):
            if value:
                clauses.append(f"{column} = ?")
                parameters.append(value)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with closing(connect(self.database_path)) as connection:
            total = int(connection.execute(
                f"SELECT COUNT(*) FROM quarantine_items {where}", parameters
            ).fetchone()[0])
            rows = connection.execute(
                f"SELECT * FROM quarantine_items {where} ORDER BY operation_id DESC, id LIMIT ? OFFSET ?",
                (*parameters, page_size, (page - 1) * page_size),
            ).fetchall()
        return QuarantineItemList(
            items=[self._quarantine_from_row(row) for row in rows],
            page=PageInfo(page=page, page_size=page_size, total=total),
        )

    def save_inventory_run(
        self,
        *,
        scan_id: str,
        platform: str,
        coverage: Any,
        rules_version: str,
        checkpoint: dict[str, Any],
        objects: Iterable[Any],
        evidence: Iterable[Any],
    ) -> None:
        with closing(connect(self.database_path)) as connection:
            connection.execute(
                """
                INSERT INTO inventory_scan_profiles(
                    scan_id, profile, platform, content_read, hash_mode,
                    coverage_json, rules_version, created_at
                ) VALUES (?, 'inventory_metadata', ?, 0, 'none', ?, ?, ?)
                ON CONFLICT(scan_id) DO NOTHING
                """,
                (scan_id, platform, _dump(coverage), rules_version, utc_now().isoformat()),
            )
            connection.execute(
                """
                INSERT INTO inventory_checkpoints(
                    checkpoint_id, scan_id, status, last_relative_path,
                    collected_entries, skipped_entries, payload_json, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(checkpoint_id) DO UPDATE SET
                    status=excluded.status,
                    last_relative_path=excluded.last_relative_path,
                    collected_entries=excluded.collected_entries,
                    skipped_entries=excluded.skipped_entries,
                    payload_json=excluded.payload_json,
                    updated_at=excluded.updated_at
                """,
                (
                    checkpoint["checkpoint_id"],
                    scan_id,
                    checkpoint["status"],
                    checkpoint.get("last_relative_path"),
                    checkpoint["collected_entries"],
                    checkpoint["skipped_entries"],
                    _dump(checkpoint),
                    utc_now().isoformat(),
                ),
            )
            ordered_objects = sorted(
                list(objects),
                key=lambda item: (
                    item.relative_path.count("/"),
                    item.relative_path.casefold(),
                    item.object_id,
                ),
            )
            for item in ordered_objects:
                payload = item.model_dump(mode="json")
                connection.execute(
                    """
                    INSERT INTO governance_objects(
                        object_id, scan_id, schema_version, object_type, parent_object_id,
                        logical_size_bytes, allocated_size_bytes,
                        reclaimable_estimate_bytes, payload_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(object_id) DO NOTHING
                    """,
                    (
                        payload["object_id"],
                        scan_id,
                        payload["schema_version"],
                        payload["object_type"],
                        payload["parent_object_id"],
                        payload["logical_size_bytes"],
                        payload["allocated_size_bytes"],
                        payload["reclaimable_estimate_bytes"],
                        _dump(payload),
                    ),
                )
            for item in evidence:
                payload = item.model_dump(mode="json")
                connection.execute(
                    """
                    INSERT INTO governance_evidence(
                        evidence_id, scan_id, object_id, evidence_type, payload_json
                    ) VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(evidence_id) DO NOTHING
                    """,
                    (
                        payload["evidence_id"],
                        scan_id,
                        payload["object_id"],
                        payload["evidence_type"],
                        _dump(payload),
                    ),
                )
            connection.commit()

    def save_snapshot(self, snapshot: Any) -> None:
        payload = snapshot.model_dump(mode="json")
        with closing(connect(self.database_path)) as connection:
            connection.execute(
                """
                INSERT INTO report_snapshots(
                    snapshot_id, scan_id, schema_version, snapshot_sha256,
                    payload_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(snapshot_id) DO NOTHING
                """,
                (
                    payload["snapshot_id"],
                    payload["scan_id"],
                    payload["schema_version"],
                    payload["snapshot_sha256"],
                    _dump(payload),
                    payload["generated_at"],
                ),
            )
            connection.commit()

    def save_packet(self, packet: Any) -> None:
        payload = packet.model_dump(mode="json")
        with closing(connect(self.database_path)) as connection:
            connection.execute(
                """
                INSERT INTO analysis_packets(
                    packet_id, snapshot_id, schema_version, artifact_privacy_mode,
                    packet_sha256, payload_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(packet_id) DO NOTHING
                """,
                (
                    payload["packet_id"],
                    payload["snapshot_id"],
                    payload["schema_version"],
                    payload["artifact_privacy_mode"],
                    payload["packet_sha256"],
                    _dump(payload),
                    payload["generated_at"],
                ),
            )
            connection.commit()

    @staticmethod
    def _insert_analysis_records(
        connection: sqlite3.Connection,
        analysis_payload: dict[str, Any],
        receipt_payload: dict[str, Any],
    ) -> None:
        persistence_cache_key = receipt_payload["cache_key"]
        if receipt_payload["consent_receipt_id"] is not None:
            persistence_cache_key += (
                f":consent:{receipt_payload['consent_receipt_id']}"
            )
        elif analysis_payload["status"] != "ai_complete":
            persistence_cache_key += (
                f":{receipt_payload['status']}:{receipt_payload['receipt_id']}"
            )
        connection.execute(
            """
            INSERT INTO ai_analyses(
                analysis_id, packet_id, schema_version, provider, model,
                status, cache_key, payload_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(analysis_id) DO NOTHING
            """,
            (
                analysis_payload["analysis_id"],
                analysis_payload["packet_id"],
                analysis_payload["schema_version"],
                analysis_payload["provider"],
                analysis_payload["model"],
                analysis_payload["status"],
                persistence_cache_key,
                _dump(analysis_payload),
                utc_now().isoformat(),
            ),
        )
        connection.execute(
            """
            INSERT INTO model_call_receipts(
                receipt_id, analysis_id, provider, status, provider_calls,
                network_calls, payload_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(receipt_id) DO NOTHING
            """,
            (
                receipt_payload["receipt_id"],
                analysis_payload["analysis_id"],
                receipt_payload["provider"],
                receipt_payload["status"],
                receipt_payload["provider_calls"],
                receipt_payload["network_calls"],
                _dump(receipt_payload),
                utc_now().isoformat(),
            ),
        )

    def save_analysis(self, analysis: Any, receipt: Any) -> None:
        analysis_payload = analysis.model_dump(mode="json")
        receipt_payload = receipt.model_dump(mode="json")
        with closing(connect(self.database_path)) as connection:
            self._insert_analysis_records(
                connection,
                analysis_payload,
                receipt_payload,
            )
            connection.commit()

    def save_synthetic_analysis_and_finalize_consent(
        self,
        analysis: Any,
        receipt: Any,
    ) -> dict[str, Any]:
        analysis_payload = analysis.model_dump(mode="json")
        receipt_payload = receipt.model_dump(mode="json")
        consent_receipt_id = receipt_payload["consent_receipt_id"]
        if consent_receipt_id is None:
            raise ValueError("SYNTHETIC_CONSENT_REQUIRED")
        with closing(connect(self.database_path)) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    """
                    SELECT binding_json, status, created_at
                    FROM analysis_consent_receipts
                    WHERE consent_receipt_id = ?
                    """,
                    (consent_receipt_id,),
                ).fetchone()
                if row is None:
                    raise ValueError("CONSENT_NOT_FOUND")
                if row["status"] != "reserved":
                    raise ValueError("CONSENT_NOT_RESERVED")
                self._insert_analysis_records(
                    connection,
                    analysis_payload,
                    receipt_payload,
                )
                consumed_at = utc_now().isoformat()
                binding = _load(row["binding_json"], {})
                consent_receipt = {
                    **binding,
                    "status": "consumed",
                    "synthetic": True,
                    "provider_calls": receipt_payload["provider_calls"],
                    "network_calls": receipt_payload["network_calls"],
                    "input_tokens": receipt_payload["input_tokens"],
                    "cached_input_tokens": receipt_payload[
                        "cached_input_tokens"
                    ],
                    "output_tokens": receipt_payload["output_tokens"],
                    "estimated_cost": receipt_payload["estimated_cost"],
                    "latency_ms": receipt_payload["latency_ms"],
                    "fallback": receipt_payload["fallback"],
                    "created_at": row["created_at"],
                    "consumed_at": consumed_at,
                    "error_code": receipt_payload["error_code"],
                }
                updated = connection.execute(
                    """
                    UPDATE analysis_consent_receipts
                    SET receipt_json = ?, analysis_id = ?, model_receipt_id = ?,
                        status = 'consumed', consumed_at = ?
                    WHERE consent_receipt_id = ? AND status = 'reserved'
                    """,
                    (
                        _canonical_dump(consent_receipt),
                        analysis_payload["analysis_id"],
                        receipt_payload["receipt_id"],
                        consumed_at,
                        consent_receipt_id,
                    ),
                )
                if updated.rowcount != 1:
                    raise ValueError("CONSENT_NOT_RESERVED")
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        return consent_receipt

    def consume_analysis_consent(self, binding: Any) -> dict[str, Any]:
        payload = (
            binding.model_dump(mode="json")
            if hasattr(binding, "model_dump")
            else dict(binding)
        )
        serialized = _canonical_dump(payload)
        binding_sha256 = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        now = utc_now().isoformat()
        with closing(connect(self.database_path)) as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """
                SELECT *
                FROM analysis_consent_receipts
                WHERE consent_receipt_id = ? OR client_action_id = ?
                LIMIT 1
                """,
                (
                    payload["consent_receipt_id"],
                    payload["client_action_id"],
                ),
            ).fetchone()
            if existing is not None:
                if (
                    existing["consent_receipt_id"]
                    != payload["consent_receipt_id"]
                    or existing["client_action_id"] != payload["client_action_id"]
                    or existing["binding_sha256"] != binding_sha256
                ):
                    connection.rollback()
                    raise ValueError("CONSENT_BINDING_MISMATCH")
                connection.commit()
                return {
                    "consent_receipt_id": existing["consent_receipt_id"],
                    "client_action_id": existing["client_action_id"],
                    "status": existing["status"],
                    "analysis_id": existing["analysis_id"],
                    "model_receipt_id": existing["model_receipt_id"],
                    "binding_sha256": existing["binding_sha256"],
                    "created_at": existing["created_at"],
                    "consumed_at": existing["consumed_at"],
                    "newly_reserved": False,
                }
            connection.execute(
                """
                INSERT INTO analysis_consent_receipts(
                    consent_receipt_id, client_action_id, packet_id,
                    packet_sha256, binding_sha256, binding_json, status,
                    created_at, consumed_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'reserved', ?, NULL)
                """,
                (
                    payload["consent_receipt_id"],
                    payload["client_action_id"],
                    payload["packet_id"],
                    payload["packet_sha256"],
                    binding_sha256,
                    serialized,
                    now,
                ),
            )
            connection.commit()
        return {
            "consent_receipt_id": payload["consent_receipt_id"],
            "client_action_id": payload["client_action_id"],
            "status": "reserved",
            "analysis_id": None,
            "model_receipt_id": None,
            "binding_sha256": binding_sha256,
            "created_at": now,
            "consumed_at": None,
            "newly_reserved": True,
        }

    def analysis_consent_identifier_exists(
        self,
        *,
        consent_receipt_id: str,
        client_action_id: str,
    ) -> bool:
        with closing(connect(self.database_path)) as connection:
            return (
                connection.execute(
                    """
                    SELECT 1
                    FROM analysis_consent_receipts
                    WHERE consent_receipt_id = ? OR client_action_id = ?
                    LIMIT 1
                    """,
                    (consent_receipt_id, client_action_id),
                ).fetchone()
                is not None
            )

    def get_analysis_consent(
        self,
        consent_receipt_id: str,
    ) -> dict[str, Any] | None:
        with closing(connect(self.database_path)) as connection:
            row = connection.execute(
                """
                SELECT receipt_json
                FROM analysis_consent_receipts
                WHERE consent_receipt_id = ?
                """,
                (consent_receipt_id,),
            ).fetchone()
        if row is None or row["receipt_json"] is None:
            return None
        return _load(row["receipt_json"], {})

    def get_analysis_for_client_action(
        self,
        client_action_id: str,
    ) -> tuple[Any, Any, Any] | None:
        from core.analysis.schemas import (
            AIAnalysisV1,
            AnalysisConsentReceiptV1,
            ModelCallReceiptV1,
        )

        with closing(connect(self.database_path)) as connection:
            consent = connection.execute(
                """
                SELECT analysis_id, model_receipt_id, receipt_json
                FROM analysis_consent_receipts
                WHERE client_action_id = ?
                """,
                (client_action_id,),
            ).fetchone()
            if (
                consent is None
                or consent["analysis_id"] is None
                or consent["model_receipt_id"] is None
                or consent["receipt_json"] is None
            ):
                return None
            analysis = connection.execute(
                "SELECT payload_json FROM ai_analyses WHERE analysis_id = ?",
                (consent["analysis_id"],),
            ).fetchone()
            receipt = connection.execute(
                "SELECT payload_json FROM model_call_receipts WHERE receipt_id = ?",
                (consent["model_receipt_id"],),
            ).fetchone()
        if analysis is None or receipt is None:
            return None
        return (
            AIAnalysisV1.model_validate(_load(analysis["payload_json"], {})),
            ModelCallReceiptV1.model_validate(_load(receipt["payload_json"], {})),
            AnalysisConsentReceiptV1.model_validate(
                _load(consent["receipt_json"], {})
            ),
        )

    def count_analysis_consents(self) -> int:
        with closing(connect(self.database_path)) as connection:
            return int(
                connection.execute(
                    "SELECT COUNT(*) FROM analysis_consent_receipts"
                ).fetchone()[0]
            )

    def save_report_artifact(self, manifest: Any) -> None:
        payload = manifest.model_dump(mode="json")
        with closing(connect(self.database_path)) as connection:
            connection.execute(
                """
                INSERT INTO report_artifacts(
                    artifact_id, report_id, snapshot_id, packet_id, analysis_id,
                    schema_version, artifact_privacy_mode, filename,
                    workbook_sha256, manifest_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(artifact_id) DO NOTHING
                """,
                (
                    payload["artifact_id"],
                    payload["report_id"],
                    payload["snapshot_id"],
                    payload["packet_id"],
                    payload["analysis_id"],
                    payload["schema_version"],
                    payload["artifact_privacy_mode"],
                    payload["filename"],
                    payload["workbook_sha256"],
                    _dump(payload),
                    payload["generated_at"],
                ),
            )
            connection.commit()

    def get_inventory_run(self, scan_id: str) -> dict[str, Any] | None:
        with closing(connect(self.database_path)) as connection:
            profile = connection.execute(
                "SELECT * FROM inventory_scan_profiles WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()
            if profile is None:
                return None
            checkpoint = connection.execute(
                """
                SELECT payload_json
                FROM inventory_checkpoints
                WHERE scan_id = ?
                ORDER BY updated_at DESC
                LIMIT 1
                """,
                (scan_id,),
            ).fetchone()
            snapshot = connection.execute(
                """
                SELECT snapshot_id
                FROM report_snapshots
                WHERE scan_id = ?
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (scan_id,),
            ).fetchone()
        if checkpoint is None or snapshot is None:
            return None
        return {
            "scan_id": scan_id,
            "profile": profile["profile"],
            "platform": profile["platform"],
            "content_read": bool(profile["content_read"]),
            "hash_mode": profile["hash_mode"],
            "coverage": _load(profile["coverage_json"], {}),
            "rules_version": profile["rules_version"],
            "checkpoint": _load(checkpoint["payload_json"], {}),
            "snapshot_id": snapshot["snapshot_id"],
        }

    def get_snapshot(self, snapshot_id: str) -> Any | None:
        from core.inventory.models import ReportSnapshotV1

        with closing(connect(self.database_path)) as connection:
            row = connection.execute(
                "SELECT payload_json FROM report_snapshots WHERE snapshot_id = ?",
                (snapshot_id,),
            ).fetchone()
        if row is None:
            return None
        return ReportSnapshotV1.model_validate(_load(row["payload_json"], {}))

    def get_snapshot_for_scan(self, scan_id: str) -> Any | None:
        with closing(connect(self.database_path)) as connection:
            row = connection.execute(
                """
                SELECT snapshot_id
                FROM report_snapshots
                WHERE scan_id = ?
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (scan_id,),
            ).fetchone()
        return self.get_snapshot(row["snapshot_id"]) if row else None

    def get_packet(self, packet_id: str) -> Any | None:
        from core.analysis.schemas import AnalysisPacketV1

        with closing(connect(self.database_path)) as connection:
            row = connection.execute(
                "SELECT payload_json FROM analysis_packets WHERE packet_id = ?",
                (packet_id,),
            ).fetchone()
        if row is None:
            return None
        return AnalysisPacketV1.model_validate(_load(row["payload_json"], {}))

    def get_analysis(self, analysis_id: str) -> tuple[Any, Any] | None:
        from core.analysis.schemas import AIAnalysisV1, ModelCallReceiptV1

        with closing(connect(self.database_path)) as connection:
            analysis = connection.execute(
                "SELECT payload_json FROM ai_analyses WHERE analysis_id = ?",
                (analysis_id,),
            ).fetchone()
            receipt = connection.execute(
                """
                SELECT payload_json
                FROM model_call_receipts
                WHERE analysis_id = ?
                ORDER BY rowid DESC
                LIMIT 1
                """,
                (analysis_id,),
            ).fetchone()
        if analysis is None or receipt is None:
            return None
        return (
            AIAnalysisV1.model_validate(_load(analysis["payload_json"], {})),
            ModelCallReceiptV1.model_validate(_load(receipt["payload_json"], {})),
        )

    def get_analysis_for_packet_provider(
        self,
        packet_id: str,
        provider: str,
    ) -> tuple[Any, Any] | None:
        with closing(connect(self.database_path)) as connection:
            row = connection.execute(
                """
                SELECT analysis_id
                FROM ai_analyses
                WHERE packet_id = ? AND provider = ? AND status = 'ai_complete'
                ORDER BY rowid DESC
                LIMIT 1
                """,
                (packet_id, provider),
            ).fetchone()
        return self.get_analysis(row["analysis_id"]) if row else None

    def get_report_manifest(self, report_id: str) -> Any | None:
        from core.reports.models import ReportManifestV1

        with closing(connect(self.database_path)) as connection:
            row = connection.execute(
                "SELECT manifest_json FROM report_artifacts WHERE report_id = ?",
                (report_id,),
            ).fetchone()
        if row is None:
            return None
        return ReportManifestV1.model_validate(_load(row["manifest_json"], {}))

    def get_report_for_inputs(
        self,
        *,
        snapshot_id: str,
        packet_id: str,
        analysis_id: str,
    ) -> Any | None:
        with closing(connect(self.database_path)) as connection:
            row = connection.execute(
                """
                SELECT report_id
                FROM report_artifacts
                WHERE snapshot_id = ? AND packet_id = ? AND analysis_id = ?
                LIMIT 1
                """,
                (snapshot_id, packet_id, analysis_id),
            ).fetchone()
        return self.get_report_manifest(row["report_id"]) if row else None

    @staticmethod
    def _scan_from_row(row: sqlite3.Row) -> ScanSession:
        return ScanSession(
            id=row["id"], status=row["status"], requested_paths=_load(row["requested_paths_json"], []),
            started_at=row["started_at"], finished_at=row["finished_at"], current_path=row["current_path"],
            files_seen=row["files_seen"], files_indexed=row["files_indexed"],
            files_skipped=row["files_skipped"], bytes_seen=row["bytes_seen"],
            error_summary=_load(row["error_summary_json"], []),
        )

    @staticmethod
    def _asset_from_row(row: sqlite3.Row | dict[str, Any]) -> Asset:
        return Asset(
            id=row["id"], abs_path=row["abs_path"], path_hash=row["path_hash"],
            file_hash=row["file_hash"], partial_hash=row["partial_hash"], hash_status=row["hash_status"],
            size_bytes=row["size_bytes"], ext=row["ext"], mime=row["mime"], category=row["category"],
            source_hint=row["source_hint"], created_at=row["created_at"], modified_at=row["modified_at"],
            accessed_at=row["accessed_at"], status=row["status"], scan_session_id=row["scan_session_id"],
            risk_flags=_load(row["risk_flags_json"], []),
        )

    @staticmethod
    def _suggestion_from_row(row: sqlite3.Row) -> Suggestion:
        return Suggestion(
            id=row["id"], asset_id=row["asset_id"], dup_group_id=row["dup_group_id"],
            category=row["category"], risk_level=row["risk_level"], proposed_action=row["proposed_action"],
            reason=row["reason"], evidence=SuggestionEvidence(items=_load(row["evidence_json"], [])),
            reversible=bool(row["reversible"]), default_selected=bool(row["default_selected"]),
            status=row["status"], created_at=row["created_at"],
        )

    @staticmethod
    def _receipt_from_row(row: sqlite3.Row, results: list[sqlite3.Row]) -> OperationReceipt:
        return OperationReceipt(
            id=row["id"], operation_plan_id=row["operation_plan_id"], action_type=row["action_type"],
            status=row["status"], reversible=True, file_count=row["file_count"],
            total_size_bytes=row["total_size_bytes"], started_at=row["started_at"],
            finished_at=row["finished_at"], affects_cloud_sync=bool(row["affects_cloud_sync"]),
            rule_version=row["rule_version"], provider_version=row["provider_version"],
            file_results=[OperationFileResult(
                asset_id=item["asset_id"], status=item["status"], original_path=item["original_path"],
                quarantine_item_id=item["quarantine_item_id"],
                error=ErrorResponse.model_validate(_load(item["error_json"], {})) if item["error_json"] else None,
            ) for item in results],
        )

    @staticmethod
    def _quarantine_from_row(row: sqlite3.Row) -> QuarantineItem:
        return QuarantineItem(
            id=row["id"], operation_id=row["operation_id"], asset_id=row["asset_id"],
            original_path=row["original_path"], quarantine_path=row["quarantine_path"],
            original_mtime=row["original_mtime"], original_size_bytes=row["original_size_bytes"],
            file_hash=row["file_hash"], status=row["status"], error_message=row["error_message"],
        )
