from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import stat
import sys
from typing import Iterable, Iterator

from core.collectors.base import (
    CancelToken,
    CollectionResult,
    CollectionState,
    ProductCounters,
    ScanFactBatch,
    ScopeSpec,
)
from core.collectors.checkpoint import CollectorCheckpoint
from core.collectors.checkpoint import CollectorCheckpointError
from core.collectors.platform.base import PlatformMetadataAdapter
from core.collectors.platform.macos import MacOSMetadataAdapter
from core.collectors.platform.windows import WindowsMetadataAdapter
from core.inventory.models import CoverageV1, ScanFactV1, TimeEvidenceV1


class CollectorScopeError(ValueError):
    pass


def default_metadata_adapter(
    platform_name: str | None = None,
) -> PlatformMetadataAdapter:
    resolved = platform_name or sys.platform
    if resolved == "win32":
        return WindowsMetadataAdapter()
    return MacOSMetadataAdapter()


class FileSystemCollector:
    def __init__(
        self,
        adapter: PlatformMetadataAdapter | None = None,
        *,
        batch_size: int = 128,
    ):
        self.adapter = adapter or default_metadata_adapter()
        self.batch_size = batch_size
        self.counters = ProductCounters()
        self._walk_errors: dict[Path, str] = {}

    @staticmethod
    def _validated_scope(scope: ScopeSpec) -> tuple[Path, Path]:
        root = scope.root
        allowed = scope.allowed_root
        if not root.is_absolute() or not allowed.is_absolute():
            raise CollectorScopeError("scope 与 allowed_root 必须为绝对路径")
        if root.is_symlink() or getattr(
            os.path,
            "isjunction",
            lambda _value: False,
        )(root):
            raise CollectorScopeError("scope 不能是符号链接或 junction")
        root = root.resolve(strict=True)
        allowed = allowed.resolve(strict=True)
        if not root.is_dir() or not root.is_relative_to(allowed):
            raise CollectorScopeError("scope 必须位于显式允许的 fixture 或临时目录")
        return root, allowed

    def _manifest_paths(self, root: Path, entries: tuple[str, ...]) -> Iterable[Path]:
        for relative in entries:
            normalized = Path(os.path.abspath(root / relative))
            if not normalized.is_relative_to(root):
                raise CollectorScopeError(f"fixture entry 越界：{relative}")
            yield normalized

    @staticmethod
    def _scope_fingerprint(scope: ScopeSpec, root: Path) -> str:
        if scope.manifest_entries is not None:
            payload = f"{root}\0" + "\0".join(scope.manifest_entries)
            mode = "manifest"
        else:
            info = root.stat(follow_symlinks=False)
            payload = (
                f"{root}\0{info.st_dev}\0{info.st_ino}\0"
                f"{info.st_mtime_ns}\0{info.st_size}"
            )
            mode = "root-metadata"
        return hashlib.sha256(
            f"{scope.scope_id}\0{mode}\0{payload}".encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _validate_checkpoint(
        checkpoint: CollectorCheckpoint,
        *,
        scope: ScopeSpec,
        expected_checkpoint_id: str,
    ) -> None:
        if checkpoint.scan_id != scope.scope_id:
            raise CollectorCheckpointError("checkpoint scan_id 与 scope 不匹配")
        if checkpoint.status not in {"running", "cancelled", "partial"}:
            raise CollectorCheckpointError(
                f"checkpoint status={checkpoint.status} 不允许恢复"
            )
        if checkpoint.checkpoint_id != expected_checkpoint_id:
            raise CollectorCheckpointError("checkpoint scope fingerprint 不匹配")
        processed = checkpoint.collected_entries + checkpoint.skipped_entries
        if processed and checkpoint.last_relative_path is None:
            raise CollectorCheckpointError("checkpoint cursor 缺失")

    def _walk_paths(self, root: Path) -> Iterable[Path]:
        stack = [root]
        while stack:
            directory = stack.pop()
            try:
                entries = sorted(os.scandir(directory), key=lambda item: item.name.casefold())
            except OSError as exc:
                self._walk_errors[directory] = type(exc).__name__.upper()
                yield directory
                continue
            for entry in entries:
                path = Path(entry.path)
                try:
                    is_link = entry.is_symlink() or getattr(
                        os.path,
                        "isjunction",
                        lambda _value: False,
                    )(entry.path)
                    is_directory = entry.is_dir(follow_symlinks=False)
                    if not is_link and is_directory:
                        try:
                            probe = os.scandir(path)
                            probe.close()
                        except OSError as exc:
                            self._walk_errors[path] = (
                                type(exc).__name__.upper()
                            )
                        else:
                            stack.append(path)
                except OSError as exc:
                    self._walk_errors[path] = type(exc).__name__.upper()
                yield path

    @staticmethod
    def _file_type(info: os.stat_result) -> str:
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        if getattr(info, "st_file_attributes", 0) & reparse_flag:
            return "symlink"
        if stat.S_ISLNK(info.st_mode):
            return "symlink"
        if stat.S_ISDIR(info.st_mode):
            return "directory"
        if stat.S_ISREG(info.st_mode):
            return "file"
        return "other"

    def _fact(self, scope: ScopeSpec, root: Path, path: Path) -> ScanFactV1:
        relative = path.relative_to(root).as_posix()
        try:
            forced_error = self._walk_errors.get(path)
            if forced_error:
                if forced_error == "PERMISSIONERROR":
                    raise PermissionError(forced_error)
                raise OSError(forced_error)
            info = path.stat(follow_symlinks=False)
            file_type = self._file_type(info)
            platform = self.adapter.from_stat(path, info)
            status_value = "skipped" if file_type in {"symlink", "other"} else "collected"
            if file_type == "symlink":
                error_code = (
                    "SYMLINK_NOT_FOLLOWED"
                    if path.is_symlink()
                    else "REPARSE_POINT_NOT_FOLLOWED"
                )
            else:
                error_code = (
                    "UNSUPPORTED_FILE_TYPE"
                    if file_type == "other"
                    else None
                )
            logical = int(info.st_size) if file_type == "file" else 0
            allocated = platform.allocated_size_bytes if file_type == "file" else 0
            created = platform.created
            modified = platform.modified
            accessed = platform.accessed
        except OSError as exc:
            file_type = "other"
            permission_denied = isinstance(exc, PermissionError)
            status_value = "permission_denied" if permission_denied else "skipped"
            error_code = (
                "PERMISSION_DENIED"
                if permission_denied
                else self._walk_errors.get(path, type(exc).__name__.upper())
            )
            logical = 0
            allocated = None
            unavailable = TimeEvidenceV1(
                value=None,
                source="unavailable",
                evidence_type="unavailable",
                confidence="unknown",
                platform=self.adapter.platform_name,
                limitation="权限不足，未取得时间元数据。",
            )
            created = modified = accessed = unavailable
        fact_id = "fact_" + hashlib.sha256(
            f"{scope.scope_id}\0{relative}\0{file_type}".encode("utf-8")
        ).hexdigest()[:24]
        return ScanFactV1(
            fact_id=fact_id,
            scope_id=scope.scope_id,
            relative_path=relative,
            absolute_path=str(path),
            name=path.name,
            parent_relative_path=(
                path.parent.relative_to(root).as_posix() if path.parent != root else None
            ),
            file_type=file_type,
            status=status_value,
            error_code=error_code,
            logical_size_bytes=logical,
            allocated_size_bytes=allocated,
            reclaimable_estimate_bytes=None,
            extension=path.suffix.casefold() if file_type == "file" else "",
            modified=modified,
            created=created,
            accessed=accessed,
            platform=self.adapter.platform_name,
        )

    def collect(
        self,
        scope: ScopeSpec,
        profile: str,
        checkpoint: CollectorCheckpoint | None,
        cancel_token: CancelToken,
    ) -> Iterator[ScanFactBatch]:
        if profile != "inventory_metadata":
            raise ValueError("迭代 1 Collector 只允许 inventory_metadata")
        self._walk_errors = {}
        root, _ = self._validated_scope(scope)
        scope_fingerprint = self._scope_fingerprint(scope, root)
        initial = CollectorCheckpoint.initial(
            scope.scope_id,
            scope_fingerprint=scope_fingerprint,
        )
        if checkpoint is not None:
            self._validate_checkpoint(
                checkpoint,
                scope=scope,
                expected_checkpoint_id=initial.checkpoint_id,
            )
        current = checkpoint or initial
        state = CollectionState(
            collected_entries=current.collected_entries,
            skipped_entries=current.skipped_entries,
        )
        paths = (
            self._manifest_paths(root, scope.manifest_entries)
            if scope.manifest_entries is not None
            else self._walk_paths(root)
        )
        requested = len(scope.manifest_entries) if scope.manifest_entries is not None else 0
        batch: list[ScanFactV1] = []
        resume_cursor = checkpoint.last_relative_path if checkpoint is not None else None
        resume_pending = resume_cursor is not None
        resume_prefix_entries = 0
        cancelled_before_cursor = False
        for path in paths:
            if cancel_token.cancelled:
                current = current.model_copy(
                    update={
                        "status": "cancelled",
                        "last_relative_path": current.last_relative_path,
                        "updated_at": datetime.now(timezone.utc),
                    }
                )
                cancelled_before_cursor = resume_pending
                break
            if resume_pending:
                resume_prefix_entries += 1
                relative = path.relative_to(root).as_posix()
                if relative == resume_cursor:
                    expected_prefix = (
                        current.collected_entries + current.skipped_entries
                    )
                    if resume_prefix_entries != expected_prefix:
                        raise CollectorCheckpointError(
                            "checkpoint cursor 与累计条目数不一致"
                        )
                    resume_pending = False
                continue
            fact = self._fact(scope, root, path)
            state.facts.append(fact)
            batch.append(fact)
            if fact.status == "collected":
                state.collected_entries += 1
            elif fact.status == "permission_denied":
                state.permission_gaps.append(fact.relative_path)
                state.skipped_entries += 1
            elif fact.status == "skipped":
                state.skipped_entries += 1
            current = current.model_copy(
                update={
                    "last_relative_path": fact.relative_path,
                    "collected_entries": state.collected_entries,
                    "skipped_entries": state.skipped_entries,
                    "updated_at": datetime.now(timezone.utc),
                }
            )
            if len(batch) >= self.batch_size:
                coverage = self._coverage(state, requested, cancel_token.cancelled)
                yield ScanFactBatch(
                    facts=tuple(batch),
                    coverage=coverage,
                    checkpoint=current,
                    final=False,
                )
                batch = []
        if resume_pending and not cancelled_before_cursor:
            raise CollectorCheckpointError("checkpoint cursor 不存在于当前 scope")
        final_status = "cancelled" if cancel_token.cancelled else (
            "partial" if state.skipped_entries else "completed"
        )
        current = current.model_copy(
            update={"status": final_status, "updated_at": datetime.now(timezone.utc)}
        )
        coverage = self._coverage(state, requested, cancel_token.cancelled)
        yield ScanFactBatch(
            facts=tuple(batch),
            coverage=coverage,
            checkpoint=current,
            final=True,
        )

    @staticmethod
    def _coverage(
        state: CollectionState,
        requested: int,
        cancelled: bool,
    ) -> CoverageV1:
        return CoverageV1(
            requested_entries=(
                requested
                or state.collected_entries + state.skipped_entries
            ),
            collected_entries=state.collected_entries,
            skipped_entries=state.skipped_entries,
            permission_gaps=sorted(state.permission_gaps),
            cancelled=cancelled,
        )

    def collect_all(
        self,
        scope: ScopeSpec,
        *,
        profile: str = "inventory_metadata",
        checkpoint: CollectorCheckpoint | None = None,
        cancel_token: CancelToken | None = None,
    ) -> CollectionResult:
        token = cancel_token or CancelToken()
        facts: list[ScanFactV1] = []
        final: ScanFactBatch | None = None
        for item in self.collect(scope, profile, checkpoint, token):
            facts.extend(item.facts)
            final = item
        if final is None:
            raise RuntimeError("Collector 未生成最终 batch")
        return CollectionResult(
            facts=tuple(facts),
            coverage=final.coverage,
            checkpoint=final.checkpoint,
            counters=self.counters,
        )
