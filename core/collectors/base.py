from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Protocol

from core.collectors.checkpoint import CollectorCheckpoint
from core.inventory.models import CoverageV1, ScanFactV1


@dataclass(frozen=True, slots=True)
class ScopeSpec:
    scope_id: str
    root: Path
    allowed_root: Path
    manifest_entries: tuple[str, ...] | None = None


@dataclass(slots=True)
class CancelToken:
    cancelled: bool = False

    def cancel(self) -> None:
        self.cancelled = True


@dataclass(slots=True)
class ProductCounters:
    product_content_reads: int = 0
    product_file_hashes: int = 0
    network_calls: int = 0


@dataclass(frozen=True, slots=True)
class ScanFactBatch:
    facts: tuple[ScanFactV1, ...]
    coverage: CoverageV1
    checkpoint: CollectorCheckpoint
    final: bool


@dataclass(frozen=True, slots=True)
class CollectionResult:
    facts: tuple[ScanFactV1, ...]
    coverage: CoverageV1
    checkpoint: CollectorCheckpoint
    counters: ProductCounters


class CollectorPort(Protocol):
    def collect(
        self,
        scope: ScopeSpec,
        profile: str,
        checkpoint: CollectorCheckpoint | None,
        cancel_token: CancelToken,
    ) -> Iterator[ScanFactBatch]: ...


@dataclass(slots=True)
class CollectionState:
    facts: list[ScanFactV1] = field(default_factory=list)
    permission_gaps: list[str] = field(default_factory=list)
    collected_entries: int = 0
    skipped_entries: int = 0
