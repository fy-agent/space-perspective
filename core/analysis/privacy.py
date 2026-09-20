from __future__ import annotations

import getpass
import json
import re
import socket
from typing import Any

from pydantic import Field

from core.analysis.schemas import AnalysisPacketV1
from core.inventory.models import StrictModel, canonical_json


ABSOLUTE_PATH = re.compile(
    r"(?:[A-Za-z]:\\(?:Users|Windows|Program Files)\\|/(?:Users|home|private|var|tmp)/)"
)
EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
SECRET = re.compile(
    r"\b(?:sk-[A-Za-z0-9_-]{12,}|(?:api[_-]?key|token|secret)\s*[:=]\s*\S+)",
    re.IGNORECASE,
)
FORBIDDEN_FIELDS = {
    "absolute_path",
    "file_hash",
    "partial_hash",
    "file_content",
    "content_bytes",
    "sqlite_path",
    "hostname",
    "username",
}


class PrivacyLintResult(StrictModel):
    passed: bool
    issue_codes: list[str]
    packet_bytes: int = Field(ge=0)
    max_packet_bytes: int = Field(ge=1)


def _keys(value: Any) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {key for nested in value.values() for key in _keys(nested)}
    if isinstance(value, list):
        return {key for nested in value for key in _keys(nested)}
    return set()


def lint_share_safe_packet(
    packet: AnalysisPacketV1,
    *,
    max_packet_bytes: int = 256_000,
) -> PrivacyLintResult:
    payload = packet.model_dump(mode="json")
    serialized = canonical_json(payload)
    issues: set[str] = set()
    if packet.artifact_privacy_mode != "share_safe":
        issues.add("NOT_SHARE_SAFE_MODE")
    if _keys(payload) & FORBIDDEN_FIELDS:
        issues.add("FORBIDDEN_FIELD")
    if ABSOLUTE_PATH.search(serialized):
        issues.add("ABSOLUTE_PATH")
    username = getpass.getuser()
    if username and len(username) >= 3 and username.casefold() in serialized.casefold():
        issues.add("USERNAME")
    hostname = socket.gethostname()
    if hostname and len(hostname) >= 3 and hostname.casefold() in serialized.casefold():
        issues.add("HOSTNAME")
    if EMAIL.search(serialized):
        issues.add("EMAIL")
    if SECRET.search(serialized):
        issues.add("SECRET_PATTERN")
    packet_bytes = len(serialized.encode("utf-8"))
    if packet_bytes > max_packet_bytes:
        issues.add("PACKET_TOO_LARGE")
    return PrivacyLintResult(
        passed=not issues,
        issue_codes=sorted(issues),
        packet_bytes=packet_bytes,
        max_packet_bytes=max_packet_bytes,
    )


def privacy_diff(
    local_full: AnalysisPacketV1,
    share_safe: AnalysisPacketV1,
) -> dict[str, Any]:
    local_locations = sum(item.location is not None for item in local_full.top_objects)
    safe_locations = sum(item.location is not None for item in share_safe.top_objects)
    return {
        "schema_version": "1.0",
        "local_full_packet_id": local_full.packet_id,
        "share_safe_packet_id": share_safe.packet_id,
        "object_count_equal": len(local_full.top_objects) == len(share_safe.top_objects),
        "local_full_locations": local_locations,
        "share_safe_parent_refs": safe_locations,
        "display_names_pseudonymized": all(
            item.display_name.startswith(f"{item.object_type}-")
            for item in share_safe.top_objects
        ),
        "share_safe_lint": lint_share_safe_packet(share_safe).model_dump(mode="json"),
    }
