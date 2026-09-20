from __future__ import annotations

import os
from pathlib import Path
import socket

import pytest

from core.inventory.models import canonical_json
from core.benchmarks.synthetic_metadata import (
    EXPECTED_ROLLING_CHECKSUMS,
    SCALE_GENERATOR_VERSION,
    SUPPORTED_SCALES,
    ScaleBenchmarkStore,
    build_budgeted_scale_packet,
    build_scale_snapshot,
    collect_synthetic_metadata,
    iter_synthetic_entries,
)
from core.reports.validation import validate_workbook
from core.reports.view_model import build_report_view_model
from core.reports.workbook import render_workbook
from core.analysis.orchestrator import ProductAnalysisCache, analyze_packet
import core.scanner.hashing as p0_hashing


def test_generator_is_deterministic_and_rejects_uncontracted_scale() -> None:
    first = list(iter_synthetic_entries(10_000, start_ordinal=9990))
    second = list(iter_synthetic_entries(10_000, start_ordinal=9990))

    assert SUPPORTED_SCALES == (10_000, 100_000, 1_000_000)
    assert first == second
    assert [item.ordinal for item in first] == list(range(9990, 10_000))
    assert all(item.relative_path.startswith("bucket-") for item in first)

    with pytest.raises(ValueError, match="scale"):
        list(iter_synthetic_entries(9_999))


def test_sqlite_checkpoint_cancel_reopen_resume_and_duplicate_batch_are_exact(
    tmp_path: Path,
    monkeypatch,
) -> None:
    database = tmp_path / "benchmark.sqlite3"
    first = collect_synthetic_metadata(
        database,
        scale=10_000,
        batch_size=512,
        cancel_after_entries=2_048,
    )
    assert first.state.status == "cancelled"
    assert first.state.next_ordinal == 2_048
    assert first.cancel_detection_latency_seconds <= 2.0

    store = ScaleBenchmarkStore(database)
    duplicate = list(iter_synthetic_entries(10_000, start_ordinal=0))[:512]
    before = store.load()
    after = store.apply_batch(duplicate)
    assert after.next_ordinal == before.next_ordinal
    assert after.rolling_checksum == before.rolling_checksum

    with pytest.raises(ValueError, match="部分重叠"):
        store.apply_batch(
            list(iter_synthetic_entries(10_000, start_ordinal=2_000))[:512]
        )
    with pytest.raises(ValueError, match="不连续"):
        store.apply_batch(
            list(iter_synthetic_entries(10_000, start_ordinal=3_000))[:512]
        )
    with pytest.raises(ValueError, match="不匹配"):
        ScaleBenchmarkStore(database, scale=100_000)

    rollback_before = store.load()

    def fail_write(*_args, **_kwargs):
        raise RuntimeError("controlled transaction failure")

    monkeypatch.setattr(store, "_write_state", fail_write)
    with pytest.raises(RuntimeError, match="controlled transaction failure"):
        store.apply_batch(
            list(iter_synthetic_entries(10_000, start_ordinal=2_048))[:512]
        )
    assert store.load() == rollback_before

    resumed = collect_synthetic_metadata(
        database,
        scale=10_000,
        batch_size=777,
    )
    clean_database = tmp_path / "clean.sqlite3"
    clean = collect_synthetic_metadata(
        clean_database,
        scale=10_000,
        batch_size=1_000,
    )

    assert resumed.state.status == "completed"
    assert resumed.state.next_ordinal == 10_000
    assert resumed.state.collected_entries == 10_000
    assert resumed.state.rolling_checksum == clean.state.rolling_checksum
    assert resumed.state.rolling_checksum == EXPECTED_ROLLING_CHECKSUMS[10_000]
    assert resumed.state.logical_size_bytes == clean.state.logical_size_bytes
    assert resumed.state.directory_buckets == clean.state.directory_buckets


def test_bounded_scale_snapshot_packet_and_workbook_are_valid(
    tmp_path: Path,
) -> None:
    result = collect_synthetic_metadata(
        tmp_path / "benchmark.sqlite3",
        scale=10_000,
        batch_size=1_000,
    )
    snapshot = build_scale_snapshot(result.state)
    packet = build_budgeted_scale_packet(snapshot)
    outcome = analyze_packet(
        packet,
        provider="none",
        cache=ProductAnalysisCache(),
    )
    view = build_report_view_model(
        snapshot,
        packet,
        outcome.analysis,
        outcome.receipt,
    )
    workbook = tmp_path / "scale.xlsx"
    render_workbook(view, workbook)
    validation = validate_workbook(
        workbook,
        view=view,
        snapshot=snapshot,
        packet=packet,
        analysis=outcome.analysis,
    )

    assert result.state.generator_version == SCALE_GENERATOR_VERSION
    assert snapshot.coverage.requested_entries == 10_000
    assert snapshot.coverage.collected_entries == 10_000
    assert len(snapshot.objects) <= 1_224
    assert len(packet.top_objects) <= 200
    assert len(canonical_json(packet).encode("utf-8")) <= 48_000
    assert packet.analysis_execution_mode == "none"
    assert outcome.receipt.provider_calls == 0
    assert outcome.receipt.network_calls == 0
    assert validation["zip_integrity"] is True
    assert validation["reopen_validated"] is True
    assert validation["formula_errors"] == 0


def test_synthetic_collection_has_no_source_io_hash_network_or_file_actions(
    tmp_path: Path,
    monkeypatch,
) -> None:
    def forbidden(*_args, **_kwargs):
        raise AssertionError("synthetic collection crossed a prohibited surface")

    monkeypatch.setattr(os, "scandir", forbidden)
    monkeypatch.setattr(Path, "open", forbidden)
    monkeypatch.setattr(Path, "unlink", forbidden)
    monkeypatch.setattr(Path, "rename", forbidden)
    monkeypatch.setattr(Path, "replace", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(p0_hashing, "partial_sha256", forbidden)
    monkeypatch.setattr(p0_hashing, "full_sha256", forbidden)

    result = collect_synthetic_metadata(
        tmp_path / "benchmark.sqlite3",
        scale=10_000,
        batch_size=2_000,
    )

    assert result.state.status == "completed"
    assert result.state.collected_entries == 10_000
