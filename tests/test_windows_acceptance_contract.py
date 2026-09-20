from __future__ import annotations

from pathlib import Path
import re

import yaml

from scripts.windows_acceptance import build_environment_report


ROOT = Path(__file__).parents[1]


def test_non_windows_environment_is_blocked_not_passed() -> None:
    report = build_environment_report(os_name="posix", system="Darwin")

    assert report["status"] == "blocked"
    assert report["blockers"] == ["NATIVE_WINDOWS_REQUIRED"]
    assert report["evidence_level"] == "code_audit"


def test_windows_workflow_is_pinned_and_runs_both_gates() -> None:
    workflow_path = ROOT / ".github" / "workflows" / "windows-acceptance.yml"
    workflow = yaml.load(workflow_path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)

    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["windows-p0"]
    assert job["runs-on"] == "windows-2025"
    uses = [step["uses"] for step in job["steps"] if "uses" in step]
    assert uses
    assert all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", value) for value in uses)
    commands = "\n".join(step.get("run", "") for step in job["steps"])
    assert "scripts/check_all.py" in commands
    assert "scripts/windows_acceptance.py" in commands

    report_job = workflow["jobs"]["windows-report"]
    assert report_job["runs-on"] == "windows-2025"
    report_uses = [
        step["uses"]
        for step in report_job["steps"]
        if "uses" in step
    ]
    assert report_uses
    assert all(
        re.fullmatch(r"[^@]+@[0-9a-f]{40}", value)
        for value in report_uses
    )
    report_commands = "\n".join(
        step.get("run", "")
        for step in report_job["steps"]
    )
    assert "test_windows_metadata_adapter.py" in report_commands
    assert "test_iteration6_windows_acceptance.py" in report_commands
    assert "iteration6_windows_office_acceptance.py" in report_commands
    assert "windows-ci-receipt.json" in report_commands


def test_manual_windows_runner_is_available() -> None:
    script = (ROOT / "scripts" / "windows_acceptance.ps1").read_text(encoding="utf-8")

    assert "scripts/check_all.py" in script
    assert "scripts/windows_acceptance.py" in script
    assert "scripts/iteration6_windows_office_acceptance.py" in script
    assert "$env:OS -ne \"Windows_NT\"" in script
