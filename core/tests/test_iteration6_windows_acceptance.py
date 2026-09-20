from __future__ import annotations

from pathlib import Path

import pytest

from scripts.iteration6_windows_office_acceptance import (
    build_environment_report,
    ensure_share_safe_receipt,
    validate_office_workbook,
)
from core.analysis.orchestrator import ProductAnalysisCache, analyze_packet
from core.analysis.packet import build_packet
from core.tests._inventory_helpers import make_snapshot
from core.reports.validation import validate_workbook
from core.reports.view_model import build_report_view_model
from core.reports.workbook import render_workbook


def test_non_windows_environment_is_blocked_without_fake_native_pass() -> None:
    report = build_environment_report(
        os_name="posix",
        system="Darwin",
        release="25.5.0",
        commit_sha="controlled",
    )

    assert report["status"] == "blocked"
    assert report["evidence_level"] == "code_audit"
    assert report["blockers"] == ["NATIVE_WINDOWS_REQUIRED"]
    assert report["commands"] == [
        {
            "name": "iteration6_windows_fixture_runner",
            "command": (
                "uv run python "
                "scripts/iteration6_windows_office_acceptance.py "
                "--evidence <receipt> --artifacts <artifacts>"
            ),
            "exit_code": 3,
        }
    ]
    assert report["product_counters"] == {
        "product_content_reads": 0,
        "product_file_hashes": 0,
        "network_calls": 0,
        "file_actions": 0,
        "provider_calls": 0,
    }


def test_share_safe_receipt_rejects_paths_usernames_and_sqlite() -> None:
    ensure_share_safe_receipt(
        {
            "status": "passed",
            "fixture_id": "iteration6-controlled-v1",
            "xlsx_sha256": "a" * 64,
            "checks": [{"name": "windows_long_path", "passed": True}],
        }
    )

    with pytest.raises(ValueError, match="private"):
        ensure_share_safe_receipt({"path": r"C:\Users\runneradmin\fixture"})
    with pytest.raises(ValueError, match="private"):
        ensure_share_safe_receipt({"database": "acceptance.sqlite3"})


def test_office_structure_validator_is_stricter_than_reopen(tmp_path: Path) -> None:
    snapshot, _ = make_snapshot(tmp_path)
    packet = build_packet(
        snapshot,
        artifact_privacy_mode="share_safe",
        analysis_execution_mode="none",
    )
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
    workbook = tmp_path / "windows-office.xlsx"
    render_workbook(view, workbook)
    base_validation = validate_workbook(
        workbook,
        view=view,
        snapshot=snapshot,
        packet=packet,
        analysis=outcome.analysis,
    )

    checks = validate_office_workbook(workbook)

    assert base_validation["passed"] is True
    assert checks["passed"] is True
    assert checks["sheet_count"] == 5
    assert checks["freeze_and_filters"] is True
    assert checks["column_widths_valid"] is True
    assert checks["number_formats_valid"] is True
    assert checks["formula_cells"] == 0
    assert checks["external_links"] == 0
    assert checks["macro_parts"] == 0
    assert checks["date_cells"] >= 1
    assert checks["internal_links_valid"] is True
