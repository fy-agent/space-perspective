from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import Field

from core.inventory.models import StrictModel


class CollectorCheckpointError(ValueError):
    pass


class CollectorCheckpoint(StrictModel):
    checkpoint_id: str
    scan_id: str
    status: Literal["running", "completed", "cancelled", "partial", "failed"]
    last_relative_path: str | None
    collected_entries: int = Field(ge=0)
    skipped_entries: int = Field(ge=0)
    updated_at: datetime

    @classmethod
    def initial(
        cls,
        scan_id: str,
        *,
        scope_fingerprint: str | None = None,
    ) -> "CollectorCheckpoint":
        checkpoint_id = f"checkpoint_{scan_id}"
        if scope_fingerprint is not None:
            checkpoint_id += f"_{scope_fingerprint[:16]}"
        return cls(
            checkpoint_id=checkpoint_id,
            scan_id=scan_id,
            status="running",
            last_relative_path=None,
            collected_entries=0,
            skipped_entries=0,
            updated_at=datetime.now(timezone.utc),
        )
