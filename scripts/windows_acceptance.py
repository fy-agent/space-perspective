from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import sys
import tempfile
from typing import Any


ROOT = Path(__file__).parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.app.config import default_app_data_dir
from core.domain.rules import is_hidden
from scripts.smoke_test import run_scenario


EXIT_FAILED = 1
EXIT_BLOCKED = 3
LONG_PATH_TARGET = 280


def build_environment_report(*, os_name: str, system: str) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": "ready",
        "evidence_level": "runtime_windows",
        "environment": {
            "os_name": os_name,
            "system": system,
            "python": platform.python_version(),
        },
        "checks": [],
        "blockers": [],
    }
    if os_name != "nt" or system.casefold() != "windows":
        report["status"] = "blocked"
        report["evidence_level"] = "code_audit"
        report["blockers"] = ["NATIVE_WINDOWS_REQUIRED"]
    return report


def _record(report: dict[str, Any], name: str, passed: bool, **details: Any) -> None:
    report["checks"].append({"name": name, "passed": passed, "details": details})


def _prepare_long_path(corpus: Path, result: dict[str, Any]) -> None:
    parent = corpus / "Documents"
    filename = "long-path-scan.txt"
    while len(str(parent / filename)) <= LONG_PATH_TARGET:
        parent /= "segment-0123456789abcdef"
    parent.mkdir(parents=True, exist_ok=True)
    target = parent / filename
    target.write_text("artificial long path fixture", encoding="utf-8")
    result["length"] = len(str(target))


def _check_hidden_attribute(sandbox: Path) -> tuple[bool, str]:
    import ctypes

    target = sandbox / "windows-hidden-attribute.txt"
    target.write_text("artificial hidden fixture", encoding="utf-8")
    hidden_attribute = 0x2
    set_attributes = ctypes.windll.kernel32.SetFileAttributesW
    set_attributes.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
    set_attributes.restype = ctypes.c_int
    changed = bool(set_attributes(str(target), hidden_attribute))
    try:
        detected = changed and is_hidden(target)
    finally:
        set_attributes(str(target), 0x80)
    return detected, "hidden attribute detected" if detected else "Windows hidden attribute not detected"


def run_native_windows_acceptance(report: dict[str, Any]) -> dict[str, Any]:
    local_app_data = os.environ.get("LOCALAPPDATA")
    expected_data_dir = Path(local_app_data) / "ZiliaoGuanjia" if local_app_data else None
    actual_data_dir = default_app_data_dir()
    data_dir_ok = expected_data_dir is not None and actual_data_dir == expected_data_dir
    _record(
        report,
        "windows_app_data",
        data_dir_ok,
        local_app_data_present=local_app_data is not None,
        app_folder=actual_data_dir.name,
    )

    with tempfile.TemporaryDirectory(prefix="ziliao-guanjia-windows-") as temporary:
        sandbox = Path(temporary)
        try:
            smoke = run_scenario(sandbox / "p0")
            _record(
                report,
                "p0_native_workflow",
                smoke["scan_status"] == "completed"
                and smoke["operation_status"] == "succeeded"
                and smoke["undo_status"] == "undone",
                files_indexed=smoke["files_indexed"],
                same_volume=smoke["same_volume"],
                restored_sha256=smoke["restored_sha256"],
            )
        except Exception as exc:
            _record(report, "p0_native_workflow", False, error=type(exc).__name__, message=str(exc))

        try:
            hidden_ok, hidden_message = _check_hidden_attribute(sandbox)
            _record(report, "windows_hidden_attribute", hidden_ok, message=hidden_message)
        except Exception as exc:
            _record(report, "windows_hidden_attribute", False, error=type(exc).__name__, message=str(exc))

        long_path: dict[str, Any] = {}
        try:
            long_smoke = run_scenario(
                sandbox / "long-path",
                prepare_corpus=lambda corpus: _prepare_long_path(corpus, long_path),
            )
            long_ok = (
                int(long_path.get("length", 0)) > LONG_PATH_TARGET
                and long_smoke["scan_status"] == "completed"
            )
            _record(
                report,
                "windows_long_path_scan",
                long_ok,
                path_length=long_path.get("length"),
                files_indexed=long_smoke["files_indexed"],
            )
        except Exception as exc:
            _record(
                report,
                "windows_long_path_scan",
                False,
                path_length=long_path.get("length"),
                error=type(exc).__name__,
                message=str(exc),
            )

    failed = [check["name"] for check in report["checks"] if not check["passed"]]
    report["status"] = "failed" if failed else "passed"
    report["blockers"] = failed
    return report


def _write_report(report: dict[str, Any], evidence_path: Path | None) -> None:
    rendered = json.dumps(report, ensure_ascii=False, indent=2)
    print(rendered)
    if evidence_path is not None:
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        evidence_path.write_text(rendered + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="资料管家 Windows 原生 P0 验收")
    parser.add_argument("--evidence", type=Path, help="写入 JSON 证据文件")
    args = parser.parse_args()

    report = build_environment_report(os_name=os.name, system=platform.system())
    if report["status"] == "blocked":
        _write_report(report, args.evidence)
        return EXIT_BLOCKED
    report = run_native_windows_acceptance(report)
    _write_report(report, args.evidence)
    return 0 if report["status"] == "passed" else EXIT_FAILED


if __name__ == "__main__":
    sys.exit(main())
