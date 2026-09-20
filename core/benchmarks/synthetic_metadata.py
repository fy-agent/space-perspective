from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
import hashlib
import heapq
import json
from pathlib import Path
import sqlite3
import time
from typing import Any, Iterator, Literal
from uuid import uuid4

from core.analysis.packet import build_packet
from core.analysis.schemas import AnalysisPacketV1
from core.inventory.classification import rule_hints_for
from core.inventory.evidence import build_evidence
from core.inventory.models import (
    CoverageV1,
    GovernanceObjectV1,
    ReportSnapshotV1,
    TimeEvidenceV1,
    canonical_sha256,
    canonical_json,
)


SUPPORTED_SCALES = (10_000, 100_000, 1_000_000)
SCALE_GENERATOR_VERSION = "synthetic-metadata-v1"
DEFAULT_SEED = 20_260_727
TOP_ITEM_LIMIT = 200
EXTENSIONS = ("txt", "pdf", "zip", "dmg", "jpg", "mp4", "json", "bin")
EXPECTED_ROLLING_CHECKSUMS = {
    10_000: "dfe917bd17b082771663a46f4ac613b57619bdcdf69e53cd15658a3717144b40",
    100_000: "31503a90e0224662cc0f3479de0897b1facde65768f231c48bffb41a040895c0",
    1_000_000: "584b40c7c15c735d6c340726fb3b258c15567171cbdad47b0f5e2f76d2d794df",
}
_INITIAL_CHECKSUM = "0" * 64
_FIXED_TIMESTAMP = datetime(2026, 1, 1, tzinfo=timezone.utc)


@dataclass(frozen=True, slots=True)
class SyntheticMetadataEntry:
    ordinal: int
    relative_path: str
    directory: str
    extension: str
    logical_size_bytes: int
    allocated_size_bytes: int
    modified_epoch_seconds: int

    def checksum_bytes(self) -> bytes:
        return (
            f"{self.ordinal}\0{self.relative_path}\0{self.extension}\0"
            f"{self.logical_size_bytes}\0{self.allocated_size_bytes}\0"
            f"{self.modified_epoch_seconds}"
        ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class ScaleRunState:
    run_id: str
    scale: int
    seed: int
    generator_version: str
    status: Literal["running", "cancelled", "completed", "failed"]
    next_ordinal: int
    collected_entries: int
    skipped_entries: int
    last_relative_path: str | None
    logical_size_bytes: int
    allocated_size_bytes: int
    rolling_checksum: str
    directory_buckets: dict[str, dict[str, int]]
    extension_buckets: dict[str, dict[str, int]]
    top_items: tuple[dict[str, Any], ...]
    checkpoint_commits: int
    created_at: str
    updated_at: str


@dataclass(frozen=True, slots=True)
class ScaleCollectionResult:
    state: ScaleRunState
    wall_time_seconds: float
    cpu_time_seconds: float
    cancel_detection_latency_seconds: float | None
    batches_committed: int
    resume_start_ordinal: int


def _validate_scale(scale: int) -> None:
    if scale not in SUPPORTED_SCALES:
        raise ValueError(f"scale 必须是 {SUPPORTED_SCALES}")


def _directory_count(scale: int) -> int:
    return min(1_024, max(16, scale // 1_000))


def iter_synthetic_entries(
    scale: int,
    *,
    start_ordinal: int = 0,
    seed: int = DEFAULT_SEED,
) -> Iterator[SyntheticMetadataEntry]:
    _validate_scale(scale)
    if not 0 <= start_ordinal <= scale:
        raise ValueError("start_ordinal 必须位于 0..scale")
    directory_count = _directory_count(scale)
    for ordinal in range(start_ordinal, scale):
        extension = EXTENSIONS[(ordinal + seed) % len(EXTENSIONS)]
        bucket = (ordinal * 17 + seed) % directory_count
        directory = f"bucket-{bucket:04d}"
        logical = 1_024 + (
            (ordinal * 2_654_435_761 + seed * 97) % (64 * 1024 * 1024)
        )
        allocated = ((logical + 4_095) // 4_096) * 4_096
        yield SyntheticMetadataEntry(
            ordinal=ordinal,
            relative_path=f"{directory}/item-{ordinal:09d}.{extension}",
            directory=directory,
            extension=extension,
            logical_size_bytes=logical,
            allocated_size_bytes=allocated,
            modified_epoch_seconds=1_735_689_600 + (ordinal % 31_536_000),
        )


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _state_to_payload(state: ScaleRunState) -> str:
    payload = asdict(state)
    payload["top_items"] = list(state.top_items)
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _state_from_payload(payload: str) -> ScaleRunState:
    value = json.loads(payload)
    value["top_items"] = tuple(value["top_items"])
    return ScaleRunState(**value)


class ScaleBenchmarkStore:
    def __init__(
        self,
        database_path: Path,
        *,
        scale: int | None = None,
        seed: int = DEFAULT_SEED,
    ):
        self.database_path = database_path
        if scale is not None:
            self.initialize(scale=scale, seed=seed)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def initialize(self, *, scale: int, seed: int = DEFAULT_SEED) -> ScaleRunState:
        _validate_scale(scale)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        now = _utc_now()
        initial = ScaleRunState(
            run_id=f"scale_{scale}_{uuid4().hex[:12]}",
            scale=scale,
            seed=seed,
            generator_version=SCALE_GENERATOR_VERSION,
            status="running",
            next_ordinal=0,
            collected_entries=0,
            skipped_entries=0,
            last_relative_path=None,
            logical_size_bytes=0,
            allocated_size_bytes=0,
            rolling_checksum=_INITIAL_CHECKSUM,
            directory_buckets={},
            extension_buckets={},
            top_items=(),
            checkpoint_commits=0,
            created_at=now,
            updated_at=now,
        )
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS benchmark_state (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    scale INTEGER NOT NULL,
                    seed INTEGER NOT NULL,
                    generator_version TEXT NOT NULL,
                    status TEXT NOT NULL,
                    next_ordinal INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            existing = connection.execute(
                "SELECT payload_json FROM benchmark_state WHERE singleton = 1"
            ).fetchone()
            if existing is None:
                connection.execute(
                    """
                    INSERT INTO benchmark_state(
                        singleton, scale, seed, generator_version, status,
                        next_ordinal, payload_json, updated_at
                    ) VALUES (1, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scale,
                        seed,
                        SCALE_GENERATOR_VERSION,
                        initial.status,
                        initial.next_ordinal,
                        _state_to_payload(initial),
                        now,
                    ),
                )
                return initial
            state = _state_from_payload(existing["payload_json"])
            if (
                state.scale != scale
                or state.seed != seed
                or state.generator_version != SCALE_GENERATOR_VERSION
            ):
                raise ValueError("benchmark SQLite 与 scale/seed/generator 不匹配")
            return state

    def load(self) -> ScaleRunState:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload_json FROM benchmark_state WHERE singleton = 1"
            ).fetchone()
        if row is None:
            raise RuntimeError("benchmark state 尚未初始化")
        return _state_from_payload(row["payload_json"])

    @staticmethod
    def _apply_entries(
        state: ScaleRunState,
        entries: list[SyntheticMetadataEntry],
    ) -> ScaleRunState:
        if not entries:
            return state
        first = entries[0].ordinal
        last = entries[-1].ordinal
        if last < state.next_ordinal:
            return state
        if first < state.next_ordinal <= last:
            raise ValueError("batch 与已提交 checkpoint 部分重叠")
        if first != state.next_ordinal:
            raise ValueError("batch ordinal 不连续")
        if any(
            item.ordinal != first + index
            for index, item in enumerate(entries)
        ):
            raise ValueError("batch 内 ordinal 不连续")
        if last >= state.scale:
            raise ValueError("batch 超出 scale")

        directories = {
            key: dict(value) for key, value in state.directory_buckets.items()
        }
        extensions = {
            key: dict(value) for key, value in state.extension_buckets.items()
        }
        top_heap: list[tuple[int, int, dict[str, Any]]] = []
        for item in state.top_items:
            heapq.heappush(
                top_heap,
                (
                    int(item["logical_size_bytes"]),
                    -int(item["ordinal"]),
                    dict(item),
                ),
            )
        digest = state.rolling_checksum
        logical_total = state.logical_size_bytes
        allocated_total = state.allocated_size_bytes
        for entry in entries:
            directory = directories.setdefault(
                entry.directory,
                {"entry_count": 0, "logical_size_bytes": 0, "allocated_size_bytes": 0},
            )
            directory["entry_count"] += 1
            directory["logical_size_bytes"] += entry.logical_size_bytes
            directory["allocated_size_bytes"] += entry.allocated_size_bytes
            extension = extensions.setdefault(
                entry.extension,
                {"entry_count": 0, "logical_size_bytes": 0, "allocated_size_bytes": 0},
            )
            extension["entry_count"] += 1
            extension["logical_size_bytes"] += entry.logical_size_bytes
            extension["allocated_size_bytes"] += entry.allocated_size_bytes
            logical_total += entry.logical_size_bytes
            allocated_total += entry.allocated_size_bytes
            digest = hashlib.sha256(
                bytes.fromhex(digest) + entry.checksum_bytes()
            ).hexdigest()
            candidate = {
                "ordinal": entry.ordinal,
                "relative_path": entry.relative_path,
                "directory": entry.directory,
                "extension": entry.extension,
                "logical_size_bytes": entry.logical_size_bytes,
                "allocated_size_bytes": entry.allocated_size_bytes,
                "modified_epoch_seconds": entry.modified_epoch_seconds,
            }
            heap_key = (
                entry.logical_size_bytes,
                -entry.ordinal,
                candidate,
            )
            if len(top_heap) < TOP_ITEM_LIMIT:
                heapq.heappush(top_heap, heap_key)
            elif heap_key[:2] > top_heap[0][:2]:
                heapq.heapreplace(top_heap, heap_key)

        next_ordinal = last + 1
        status: Literal["running", "cancelled", "completed", "failed"] = (
            "completed" if next_ordinal == state.scale else "running"
        )
        top_items = tuple(
            item
            for _, _, item in sorted(
                top_heap,
                key=lambda value: (-value[0], -value[1]),
            )
        )
        return replace(
            state,
            status=status,
            next_ordinal=next_ordinal,
            collected_entries=state.collected_entries + len(entries),
            last_relative_path=entries[-1].relative_path,
            logical_size_bytes=logical_total,
            allocated_size_bytes=allocated_total,
            rolling_checksum=digest,
            directory_buckets=directories,
            extension_buckets=extensions,
            top_items=top_items,
            checkpoint_commits=state.checkpoint_commits + 1,
            updated_at=_utc_now(),
        )

    def _write_state(
        self,
        connection: sqlite3.Connection,
        state: ScaleRunState,
    ) -> None:
        connection.execute(
            """
            UPDATE benchmark_state
            SET status = ?, next_ordinal = ?, payload_json = ?, updated_at = ?
            WHERE singleton = 1
            """,
            (
                state.status,
                state.next_ordinal,
                _state_to_payload(state),
                state.updated_at,
            ),
        )

    def apply_batch(
        self,
        entries: list[SyntheticMetadataEntry],
    ) -> ScaleRunState:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT payload_json FROM benchmark_state WHERE singleton = 1"
            ).fetchone()
            if row is None:
                raise RuntimeError("benchmark state 尚未初始化")
            current = _state_from_payload(row["payload_json"])
            updated = self._apply_entries(current, entries)
            if updated != current:
                self._write_state(connection, updated)
            connection.commit()
        return updated

    def mark_cancelled(self) -> ScaleRunState:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT payload_json FROM benchmark_state WHERE singleton = 1"
            ).fetchone()
            if row is None:
                raise RuntimeError("benchmark state 尚未初始化")
            current = _state_from_payload(row["payload_json"])
            if current.status == "completed":
                return current
            updated = replace(
                current,
                status="cancelled",
                checkpoint_commits=current.checkpoint_commits + 1,
                updated_at=_utc_now(),
            )
            self._write_state(connection, updated)
            connection.commit()
        return updated


def collect_synthetic_metadata(
    database_path: Path,
    *,
    scale: int,
    batch_size: int = 10_000,
    cancel_after_entries: int | None = None,
    seed: int = DEFAULT_SEED,
) -> ScaleCollectionResult:
    _validate_scale(scale)
    if batch_size <= 0:
        raise ValueError("batch_size 必须大于 0")
    if cancel_after_entries is not None and not 1 <= cancel_after_entries < scale:
        raise ValueError("cancel_after_entries 必须位于 1..scale-1")
    store = ScaleBenchmarkStore(database_path, scale=scale, seed=seed)
    before = store.load()
    if before.status == "completed":
        return ScaleCollectionResult(
            state=before,
            wall_time_seconds=0.0,
            cpu_time_seconds=0.0,
            cancel_detection_latency_seconds=None,
            batches_committed=0,
            resume_start_ordinal=before.next_ordinal,
        )
    start_ordinal = before.next_ordinal
    start_commits = before.checkpoint_commits
    wall_started = time.perf_counter()
    cpu_started = time.process_time()
    cancel_latency: float | None = None
    batch: list[SyntheticMetadataEntry] = []
    state = before
    for entry in iter_synthetic_entries(
        scale,
        start_ordinal=start_ordinal,
        seed=seed,
    ):
        batch.append(entry)
        threshold_reached = (
            cancel_after_entries is not None
            and entry.ordinal + 1 >= cancel_after_entries
        )
        if len(batch) >= batch_size or threshold_reached:
            state = store.apply_batch(batch)
            batch = []
        if threshold_reached:
            requested_at = time.perf_counter()
            state = store.mark_cancelled()
            cancel_latency = time.perf_counter() - requested_at
            break
    if batch:
        state = store.apply_batch(batch)
    wall_time = time.perf_counter() - wall_started
    cpu_time = time.process_time() - cpu_started
    return ScaleCollectionResult(
        state=state,
        wall_time_seconds=wall_time,
        cpu_time_seconds=cpu_time,
        cancel_detection_latency_seconds=cancel_latency,
        batches_committed=state.checkpoint_commits - start_commits,
        resume_start_ordinal=start_ordinal,
    )


def _object_id(kind: str, value: str) -> str:
    return "obj_" + hashlib.sha256(f"{kind}\0{value}".encode("utf-8")).hexdigest()[:24]


def _time_evidence(value: datetime, source: str) -> TimeEvidenceV1:
    return TimeEvidenceV1(
        value=value,
        source=source,
        evidence_type="filesystem_modified",
        confidence="high",
        platform="synthetic_metadata",
        limitation="确定性 synthetic metadata，不代表真实文件系统时间。",
    )


def _object_type(extension: str) -> Literal["file", "archive", "installer"]:
    if extension in {"dmg", "exe", "msi", "pkg"}:
        return "installer"
    if extension in {"zip", "7z", "rar", "tar"}:
        return "archive"
    return "file"


def build_scale_snapshot(
    state: ScaleRunState,
    *,
    generated_at: datetime | None = None,
) -> ReportSnapshotV1:
    if state.status != "completed" or state.next_ordinal != state.scale:
        raise ValueError("只有 completed scale state 可以生成 snapshot")
    common_time = _time_evidence(_FIXED_TIMESTAMP, "synthetic_generator")
    directory_ids = {
        directory: _object_id("directory", directory)
        for directory in state.directory_buckets
    }
    objects: list[GovernanceObjectV1] = []
    for directory, values in sorted(state.directory_buckets.items()):
        objects.append(
            GovernanceObjectV1(
                object_id=directory_ids[directory],
                object_type="directory",
                parent_object_id=None,
                fact_ids=[f"fact_scale_{directory}"],
                name=directory,
                relative_path=directory,
                absolute_path=f"/synthetic/{directory}",
                logical_size_bytes=values["logical_size_bytes"],
                allocated_size_bytes=values["allocated_size_bytes"],
                reclaimable_estimate_bytes=None,
                created=common_time,
                modified=common_time,
                accessed=common_time,
                rule_hints=[],
            )
        )
    for item in state.top_items:
        relative_path = str(item["relative_path"])
        extension = str(item["extension"])
        object_type = _object_type(extension)
        objects.append(
            GovernanceObjectV1(
                object_id=_object_id("top-item", relative_path),
                object_type=object_type,
                parent_object_id=directory_ids[str(item["directory"])],
                fact_ids=[f"fact_scale_{int(item['ordinal']):09d}"],
                name=Path(relative_path).name,
                relative_path=relative_path,
                absolute_path=f"/synthetic/{relative_path}",
                logical_size_bytes=int(item["logical_size_bytes"]),
                allocated_size_bytes=int(item["allocated_size_bytes"]),
                reclaimable_estimate_bytes=None,
                created=common_time,
                modified=_time_evidence(
                    datetime.fromtimestamp(
                        int(item["modified_epoch_seconds"]),
                        tz=timezone.utc,
                    ),
                    "synthetic_generator",
                ),
                accessed=common_time,
                rule_hints=rule_hints_for(object_type),
            )
        )
    evidence = build_evidence(objects)
    coverage = CoverageV1(
        requested_entries=state.scale,
        collected_entries=state.collected_entries,
        skipped_entries=state.skipped_entries,
        permission_gaps=[],
        cancelled=False,
    )
    limitations = [
        "本报告只使用确定性 synthetic metadata，不扫描真实用户目录。",
        (
            f"{state.scale} 条原始 metadata 已压缩为 "
            f"{len(state.directory_buckets)} 个目录桶与 "
            f"{len(state.top_items)} 个确定性 Top-K 对象。"
        ),
        "目录桶与 Top-K 是层级视图，不能相加作为第二套总量。",
        "平台标记 synthetic_metadata，不证明 Windows、NTFS 或用户机器性能。",
        "inventory_metadata 不读取文件内容，也不计算文件 hash。",
        "可能可腾出未评估，因此保持 null。",
    ]
    fingerprint = {
        "schema_version": "1.0",
        "profile": "inventory_metadata",
        "platform": "synthetic_metadata",
        "rules_version": "scale-benchmark-v1",
        "content_read": False,
        "hash_mode": "none",
        "canonical_tree_logical_size_bytes": state.logical_size_bytes,
        "canonical_tree_allocated_size_bytes": state.allocated_size_bytes,
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
        "generator_version": state.generator_version,
        "seed": state.seed,
        "rolling_checksum": state.rolling_checksum,
    }
    digest = canonical_sha256(fingerprint)
    return ReportSnapshotV1(
        snapshot_id=f"snapshot_{digest[:24]}",
        snapshot_sha256=digest,
        scan_id=state.run_id,
        generated_at=generated_at or datetime.now(timezone.utc),
        platform="synthetic_metadata",
        rules_version="scale-benchmark-v1",
        canonical_tree_logical_size_bytes=state.logical_size_bytes,
        canonical_tree_allocated_size_bytes=state.allocated_size_bytes,
        reclaimable_estimate_bytes=None,
        coverage=coverage,
        limitations=limitations,
        objects=sorted(objects, key=lambda item: item.object_id),
        evidence=sorted(evidence, key=lambda item: item.evidence_id),
    )


def build_budgeted_scale_packet(
    snapshot: ReportSnapshotV1,
    *,
    max_packet_bytes: int = 256_000,
    max_input_tokens: int = 12_000,
) -> AnalysisPacketV1:
    effective_bytes = min(max_packet_bytes, max_input_tokens * 4)
    low = 1
    high = min(200, len(snapshot.objects))
    selected = None
    while low <= high:
        top_k = (low + high) // 2
        packet = build_packet(
            snapshot,
            artifact_privacy_mode="share_safe",
            analysis_execution_mode="none",
            top_k=top_k,
        )
        packet_bytes = len(canonical_json(packet).encode("utf-8"))
        if packet_bytes <= effective_bytes:
            selected = packet
            low = top_k + 1
        else:
            high = top_k - 1
    if selected is None:
        raise ValueError("scale packet 即使 Top-K=1 仍超过冻结预算")
    return selected
