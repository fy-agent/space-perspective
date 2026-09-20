from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sqlite3

import pytest

from core.db.connection import initialize_database
from core.db.repository import Repository


def _binding() -> dict[str, object]:
    return {
        "consent_receipt_id": (
            "consent_receipt_00000000-0000-4000-8000-000000000001"
        ),
        "client_action_id": (
            "client_action_00000000-0000-4000-8000-000000000001"
        ),
        "confirmed": True,
        "snapshot_id": "snapshot_fixture",
        "snapshot_sha256": "a" * 64,
        "packet_id": "packet_fixture",
        "packet_sha256": "b" * 64,
        "packet_bytes": 2048,
        "artifact_privacy_mode": "share_safe",
        "analysis_execution_mode": "cloud_metadata_minimized",
        "provider": "fake",
        "model": "fixture-analyst-v1",
        "prompt_version": "report-analysis-v1",
        "consent_schema_version": "1.0",
        "analysis_schema_version": "ai-analysis-v1",
        "disclosure_version": "synthetic-disclosure-v1",
        "cost_basis": "synthetic_zero_external_cost",
        "budget": {
            "max_provider_calls": 1,
            "max_schema_retries": 1,
            "max_input_tokens": 12_000,
            "max_output_tokens": 2_500,
            "max_packet_bytes": 256_000,
            "timeout_ms": 90_000,
            "max_estimated_cost": 0,
        },
    }


def _seed_packet(database: Path) -> None:
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            INSERT INTO inventory_scan_profiles(
                scan_id, profile, platform, content_read, hash_mode,
                coverage_json, rules_version, created_at
            ) VALUES (?, 'inventory_metadata', 'fixture', 0, 'none', '{}', '1.0', ?)
            """,
            ("scan_fixture", "2026-07-27T00:00:00+00:00"),
        )
        connection.execute(
            """
            INSERT INTO report_snapshots(
                snapshot_id, scan_id, schema_version, snapshot_sha256,
                payload_json, created_at
            ) VALUES (?, ?, '1.0', ?, '{}', ?)
            """,
            (
                "snapshot_fixture",
                "scan_fixture",
                "a" * 64,
                "2026-07-27T00:00:00+00:00",
            ),
        )
        connection.execute(
            """
            INSERT INTO analysis_packets(
                packet_id, snapshot_id, schema_version, artifact_privacy_mode,
                packet_sha256, payload_json, created_at
            ) VALUES (?, ?, '1.0', 'share_safe', ?, ?, ?)
            """,
            (
                "packet_fixture",
                "snapshot_fixture",
                "b" * 64,
                json.dumps({"packet_id": "packet_fixture"}),
                "2026-07-27T00:00:00+00:00",
            ),
        )
        connection.commit()


def test_consent_consumption_is_atomic_and_same_action_is_idempotent(
    tmp_path: Path,
) -> None:
    database = tmp_path / "consent.sqlite3"
    assert initialize_database(database) == 4
    _seed_packet(database)
    repository = Repository(database)
    binding = _binding()

    first = repository.consume_analysis_consent(binding)
    repeated = repository.consume_analysis_consent(binding)

    assert first["status"] == "reserved"
    assert first["newly_reserved"] is True
    assert repeated["status"] == "reserved"
    assert repeated["newly_reserved"] is False
    assert repeated["binding_sha256"] == first["binding_sha256"]


def test_consent_receipt_cannot_be_reused_with_different_payload(
    tmp_path: Path,
) -> None:
    database = tmp_path / "consent.sqlite3"
    initialize_database(database)
    _seed_packet(database)
    repository = Repository(database)
    binding = _binding()
    repository.consume_analysis_consent(binding)

    changed = {
        **binding,
        "client_action_id": (
            "client_action_00000000-0000-4000-8000-000000000002"
        ),
        "packet_sha256": "c" * 64,
    }

    with pytest.raises(ValueError, match="CONSENT_BINDING_MISMATCH"):
        repository.consume_analysis_consent(changed)


def test_concurrent_consent_consumption_records_one_row(tmp_path: Path) -> None:
    database = tmp_path / "consent.sqlite3"
    initialize_database(database)
    _seed_packet(database)
    repository = Repository(database)
    binding = _binding()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(lambda _: repository.consume_analysis_consent(binding), range(2))
        )

    assert sum(result["newly_reserved"] is True for result in results) == 1
    assert {result["status"] for result in results} == {"reserved"}
    assert repository.count_analysis_consents() == 1
