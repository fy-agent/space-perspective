from __future__ import annotations

import json
from pathlib import Path

from scripts.security_check import run_checks


ROOT = Path(__file__).parents[2]


def _minimal_openapi(root: Path, actions: list[str] | None = None) -> None:
    shared = root / "shared"
    shared.mkdir(parents=True, exist_ok=True)
    values = actions or ["quarantine", "ignore"]
    (shared / "openapi.yaml").write_text(
        "components:\n  schemas:\n    OperationAction:\n      enum:\n"
        + "".join(f"        - {value}\n" for value in values),
        encoding="utf-8",
    )


def test_current_project_passes_security_checks() -> None:
    assert run_checks(ROOT) == []


def test_forbidden_openapi_action_is_blocked(tmp_path: Path) -> None:
    _minimal_openapi(tmp_path, ["quarantine", "permanent_delete"])

    findings = run_checks(tmp_path)

    assert any(finding.rule == "openapi-safety" for finding in findings)


def test_scanner_file_mutation_is_blocked(tmp_path: Path) -> None:
    _minimal_openapi(tmp_path)
    scanner = tmp_path / "core" / "scanner"
    scanner.mkdir(parents=True)
    (scanner / "unsafe.py").write_text(
        "from pathlib import Path\nPath('sample').unlink()\n",
        encoding="utf-8",
    )

    findings = run_checks(tmp_path)

    assert any(finding.rule == "filesystem-mutation-boundary" for finding in findings)


def test_real_network_client_is_blocked(tmp_path: Path) -> None:
    _minimal_openapi(tmp_path)
    app = tmp_path / "core" / "app"
    app.mkdir(parents=True)
    (app / "provider.py").write_text("import requests\n", encoding="utf-8")

    findings = run_checks(tmp_path)

    assert any(finding.rule == "real-network-client" for finding in findings)


def test_gpl_direct_dependency_is_blocked(tmp_path: Path) -> None:
    _minimal_openapi(tmp_path)
    ui = tmp_path / "ui"
    package = ui / "node_modules" / "unsafe-package"
    package.mkdir(parents=True)
    (ui / "package.json").write_text(
        json.dumps({"dependencies": {"unsafe-package": "1.0.0"}}),
        encoding="utf-8",
    )
    (package / "package.json").write_text(
        json.dumps({"name": "unsafe-package", "version": "1.0.0", "license": "GPL-3.0-only"}),
        encoding="utf-8",
    )

    findings = run_checks(tmp_path)

    assert any(finding.rule == "dependency-license" for finding in findings)
