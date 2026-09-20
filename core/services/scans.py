from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import mimetypes
import os
from pathlib import Path
import stat
from typing import Iterable

from core.app.config import Settings
from core.app.models import ErrorResponse, ScanEvent, ScanRequest, ScanSession
from core.db.repository import Repository, new_id, utc_now
from core.domain.rules import assess_risk, classify_category, infer_source_hint, is_hidden
from core.operations.quarantine import normalized_device_id
from core.scanner.hashing import PARTIAL_HASH_POLICY
from core.services.intelligence import build_intelligence


class ScanInputError(ValueError):
    pass


def _timestamp(value: float) -> str:
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


class ScanService:
    def __init__(self, repository: Repository, settings: Settings):
        self.repository = repository
        self.settings = settings

    def create(self, request: ScanRequest) -> tuple[ScanSession, ScanRequest]:
        normalized_roots = self._normalize_roots(request.paths)
        normalized = ScanRequest(paths=[str(path) for path in normalized_roots], options=request.options)
        return self.repository.create_scan(normalized), normalized

    def run(self, scan_id: str, request: ScanRequest) -> None:
        counts = {"seen": 0, "indexed": 0, "skipped": 0, "bytes": 0}
        errors: Counter[str] = Counter()
        current_path: str | None = None
        self._update(scan_id, "running", current_path, counts, errors)
        self._event(scan_id, "started", current_path, counts, message="只读扫描已开始")
        try:
            roots = [Path(value) for value in request.paths]
            for root in roots:
                for path in self._walk(root, include_hidden=request.options.include_hidden):
                    if self.repository.is_scan_cancel_requested(scan_id):
                        self._finish(scan_id, "cancelled", current_path, counts, errors, "扫描已取消")
                        return
                    current_path = str(path)
                    counts["seen"] += 1
                    try:
                        info = path.stat(follow_symlinks=False)
                        if not stat.S_ISREG(info.st_mode):
                            counts["skipped"] += 1
                            errors["NOT_REGULAR_FILE"] += 1
                            continue
                        category = classify_category(path)
                        source = infer_source_hint(path, root, request.options.source_hint_override)
                        risk_subject = path.relative_to(root)
                        risk, flags = assess_risk(risk_subject)
                        asset_id = new_id("asset")
                        asset = {
                            "id": asset_id,
                            "scan_session_id": scan_id,
                            "abs_path": str(path),
                            "path_hash": hashlib.sha256(str(path).encode("utf-8")).hexdigest(),
                            "file_hash": None,
                            "partial_hash": None,
                            "hash_status": "not_started",
                            "size_bytes": int(info.st_size),
                            "ext": path.suffix.lower(),
                            "mime": mimetypes.guess_type(path.name)[0],
                            "category": category,
                            "source_hint": source,
                            "created_at": _timestamp(info.st_ctime),
                            "modified_at": _timestamp(info.st_mtime),
                            "modified_ns": int(info.st_mtime_ns),
                            "accessed_at": _timestamp(info.st_atime),
                            "device_id": normalized_device_id(info.st_dev),
                            "status": "active",
                            "risk_level": risk,
                            "risk_flags_json": json.dumps(flags, ensure_ascii=False),
                        }
                        self.repository.insert_asset(asset, [
                            {
                                "asset_id": asset_id, "key": "source_evidence",
                                "value": "path_rule_v1", "raw_json": json.dumps({"root": str(root)}, ensure_ascii=False),
                            },
                            {
                                "asset_id": asset_id, "key": "hash_policy",
                                "value": PARTIAL_HASH_POLICY, "raw_json": None,
                            },
                        ])
                        counts["indexed"] += 1
                        counts["bytes"] += int(info.st_size)
                    except OSError as exc:
                        counts["skipped"] += 1
                        code = type(exc).__name__.upper()
                        errors[code] += 1
                        self._event(scan_id, "skipped", current_path, counts, message=f"文件已跳过：{code}")
                    self._update(scan_id, "running", current_path, counts, errors)
                    self._event(scan_id, "progress", current_path, counts)
            if self.repository.is_scan_cancel_requested(scan_id):
                self._finish(scan_id, "cancelled", current_path, counts, errors, "扫描已取消")
                return
            build_intelligence(self.repository, scan_id, request.options.compute_hash)
            status_value = "partial" if errors else "completed"
            self._finish(scan_id, status_value, current_path, counts, errors, "只读扫描已完成")
        except Exception as exc:
            errors[type(exc).__name__.upper()] += 1
            self._update(scan_id, "failed", current_path, counts, errors, finished_at=utc_now())
            self._event(
                scan_id, "failed", current_path, counts, message="扫描任务失败",
                error=ErrorResponse(code="SCAN_FAILED", message=str(exc) or "扫描任务失败"),
            )

    def cancel(self, scan_id: str) -> ScanSession | None:
        session = self.repository.get_scan(scan_id)
        if session is None:
            return None
        if session.status in {"pending", "running"}:
            self.repository.request_scan_cancel(scan_id)
        return self.repository.get_scan(scan_id)

    def _normalize_roots(self, values: list[str]) -> list[Path]:
        normalized: list[Path] = []
        for value in values:
            candidate = Path(value).expanduser()
            if not candidate.is_absolute():
                raise ScanInputError("扫描目录必须使用本机绝对路径")
            if candidate.is_symlink():
                raise ScanInputError(f"扫描目录不能是符号链接：{candidate}")
            try:
                resolved = candidate.resolve(strict=True)
            except OSError as exc:
                raise ScanInputError(f"扫描目录不可访问：{candidate}") from exc
            if not resolved.is_dir():
                raise ScanInputError(f"扫描目标不是目录：{resolved}")
            if resolved == Path(resolved.anchor):
                raise ScanInputError("P0 不允许扫描整个磁盘根目录")
            if resolved not in normalized:
                normalized.append(resolved)
        return normalized

    def _walk(self, root: Path, *, include_hidden: bool) -> Iterable[Path]:
        excluded = [
            self.settings.database_path.resolve(strict=False),
            self.settings.resolved_quarantine_path.resolve(strict=False),
        ]
        stack = [root]
        while stack:
            directory = stack.pop()
            try:
                entries = list(os.scandir(directory))
            except OSError:
                continue
            for entry in entries:
                path = Path(entry.path)
                if not include_hidden and is_hidden(path):
                    continue
                resolved = path.resolve(strict=False)
                if any(resolved == item or item in resolved.parents for item in excluded):
                    continue
                try:
                    if entry.is_symlink() or getattr(os.path, "isjunction", lambda _value: False)(entry.path):
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(path)
                    elif entry.is_file(follow_symlinks=False):
                        yield path
                except OSError:
                    continue

    def _finish(
        self, scan_id: str, status_value: str, current_path: str | None,
        counts: dict[str, int], errors: Counter[str], message: str,
    ) -> None:
        self._update(scan_id, status_value, current_path, counts, errors, finished_at=utc_now())
        event_type = "cancelled" if status_value == "cancelled" else "completed"
        self._event(scan_id, event_type, current_path, counts, message=message)

    def _update(
        self, scan_id: str, status_value: str, current_path: str | None,
        counts: dict[str, int], errors: Counter[str], finished_at=None,
    ) -> None:
        self.repository.update_scan(
            scan_id, status=status_value, current_path=current_path,
            files_seen=counts["seen"], files_indexed=counts["indexed"],
            files_skipped=counts["skipped"], bytes_seen=counts["bytes"],
            error_summary=[{"code": key, "count": value} for key, value in sorted(errors.items())],
            finished_at=finished_at,
        )

    def _event(
        self, scan_id: str, event_type: str, current_path: str | None,
        counts: dict[str, int], *, message: str | None = None,
        error: ErrorResponse | None = None,
    ) -> None:
        self.repository.add_scan_event(ScanEvent(
            event_id=new_id("evt"), scan_session_id=scan_id, type=event_type,
            occurred_at=utc_now(), current_path=current_path,
            files_seen=counts["seen"], files_indexed=counts["indexed"],
            files_skipped=counts["skipped"], bytes_seen=counts["bytes"],
            message=message, error=error,
        ))
