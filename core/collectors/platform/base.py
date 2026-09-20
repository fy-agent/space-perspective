from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
from typing import Protocol

from core.inventory.models import TimeEvidenceV1


@dataclass(frozen=True, slots=True)
class PlatformMetadata:
    allocated_size_bytes: int | None
    created: TimeEvidenceV1
    modified: TimeEvidenceV1
    accessed: TimeEvidenceV1


class PlatformMetadataAdapter(Protocol):
    platform_name: str
    native_validated: bool

    def from_stat(self, path: Path, info: os.stat_result) -> PlatformMetadata: ...
