from __future__ import annotations

import ast
from dataclasses import dataclass
from importlib import metadata
import json
from pathlib import Path
import re
import sys
import tomllib
from typing import Iterable

import yaml


ROOT = Path(__file__).parents[1]
FORBIDDEN_NETWORK_MODULES = {"boto3", "httpx", "httpx2", "requests", "urllib.request"}
FORBIDDEN_SOURCE_MARKERS = ("permanent_delete", "MicroMsg.db", "Msg.db")
FORBIDDEN_FRONTEND_MARKERS = (
    "showDirectoryPicker",
    "showOpenFilePicker",
    "FileSystemFileHandle",
    "FileSystemDirectoryHandle",
    "FormData(",
)
FILESYSTEM_MUTATION_CALLS = {
    "os.remove",
    "os.rename",
    "os.replace",
    "shutil.move",
    "Path.unlink",
    "Path.rename",
    "Path.replace",
}
ALLOWED_MUTATION_PREFIXES = (Path("core/operations"), Path("core/quarantine"))
COPYLEFT_PATTERN = re.compile(r"(?<!L)GPL|AGPL", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class Finding:
    rule: str
    path: Path
    message: str
    line: int | None = None

    def render(self, root: Path) -> str:
        try:
            display_path = self.path.relative_to(root)
        except ValueError:
            display_path = self.path
        location = f"{display_path}:{self.line}" if self.line else str(display_path)
        return f"{self.rule} {location} {self.message}"


def _python_files(root: Path) -> Iterable[Path]:
    for surface in (root / "core",):
        if surface.exists():
            yield from (
                path
                for path in surface.rglob("*.py")
                if "tests" not in path.parts and "__pycache__" not in path.parts
            )


def _call_name(node: ast.Call) -> str | None:
    function = node.func
    if isinstance(function, ast.Attribute):
        owner = function.value
        if isinstance(owner, ast.Name):
            return f"{owner.id}.{function.attr}"
        if isinstance(owner, ast.Call) and isinstance(owner.func, ast.Name):
            return f"{owner.func.id}.{function.attr}"
    return None


def check_python_boundaries(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in _python_files(root):
        relative = path.relative_to(root)
        source = path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError as exc:
            findings.append(Finding("python-parse", path, exc.msg, exc.lineno))
            continue

        for marker in FORBIDDEN_SOURCE_MARKERS:
            if marker in source:
                findings.append(Finding("forbidden-capability", path, f"出现禁止能力标记 {marker}"))

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules = {alias.name for alias in node.names}
            elif isinstance(node, ast.ImportFrom):
                modules = {node.module or ""}
            else:
                modules = set()
            for module in modules:
                if module in FORBIDDEN_NETWORK_MODULES or any(
                    module.startswith(f"{blocked}.") for blocked in FORBIDDEN_NETWORK_MODULES
                ):
                    findings.append(
                        Finding("real-network-client", path, f"P0 Core 不允许网络客户端 {module}", node.lineno)
                    )

            if isinstance(node, ast.Call):
                call_name = _call_name(node)
                if call_name in FILESYSTEM_MUTATION_CALLS and not any(
                    relative.is_relative_to(prefix) for prefix in ALLOWED_MUTATION_PREFIXES
                ):
                    findings.append(
                        Finding(
                            "filesystem-mutation-boundary",
                            path,
                            f"文件变更调用 {call_name} 不在 Operations/Quarantine 边界内",
                            node.lineno,
                        )
                    )
    return findings


def check_frontend_boundaries(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    source_root = root / "ui" / "src"
    if not source_root.exists():
        return findings
    for path in source_root.rglob("*"):
        if path.suffix not in {".ts", ".tsx", ".js", ".jsx"}:
            continue
        source = path.read_text(encoding="utf-8")
        for marker in FORBIDDEN_FRONTEND_MARKERS:
            if marker in source:
                findings.append(
                    Finding("frontend-filesystem-boundary", path, f"UI 不允许直接使用 {marker}")
                )
        if re.search(r"<input[^>]+type=[\"']file[\"']", source, re.IGNORECASE):
            findings.append(Finding("frontend-upload-boundary", path, "UI 不允许文件上传控件"))
    return findings


def check_openapi_actions(root: Path) -> list[Finding]:
    path = root / "shared" / "openapi.yaml"
    if not path.exists():
        return [Finding("openapi-safety", path, "缺少 OpenAPI 契约")]
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    actions = set(
        document.get("components", {})
        .get("schemas", {})
        .get("OperationAction", {})
        .get("enum", [])
    )
    forbidden = actions & {"delete", "permanent_delete", "upload"}
    return [
        Finding("openapi-safety", path, f"动作枚举包含禁止项 {action}")
        for action in sorted(forbidden)
    ]


def _dependency_names(pyproject: Path) -> set[str]:
    if not pyproject.exists():
        return set()
    document = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    entries = list(document.get("project", {}).get("dependencies", []))
    for group in document.get("dependency-groups", {}).values():
        entries.extend(group)
    return {
        re.split(r"[<>=!~\[; ]", entry, maxsplit=1)[0].replace("_", "-").lower()
        for entry in entries
    }


def check_python_licenses(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    direct = _dependency_names(root / "pyproject.toml")
    for distribution in metadata.distributions():
        name = (distribution.metadata.get("Name") or "").replace("_", "-").lower()
        if name not in direct:
            continue
        license_text = distribution.metadata.get("License-Expression") or distribution.metadata.get("License") or ""
        if COPYLEFT_PATTERN.search(license_text):
            findings.append(
                Finding("dependency-license", root / "pyproject.toml", f"{name} 使用 {license_text}")
            )
    return findings


def check_node_licenses(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    package_json = root / "ui" / "package.json"
    if not package_json.exists():
        return findings
    document = json.loads(package_json.read_text(encoding="utf-8"))
    dependencies = set(document.get("dependencies", {})) | set(document.get("devDependencies", {}))
    for package_name in sorted(dependencies):
        metadata_path = root / "ui" / "node_modules" / package_name / "package.json"
        if not metadata_path.exists():
            continue
        package = json.loads(metadata_path.read_text(encoding="utf-8"))
        license_value = package.get("license", "")
        license_text = license_value.get("type", "") if isinstance(license_value, dict) else str(license_value)
        if COPYLEFT_PATTERN.search(license_text):
            findings.append(
                Finding("dependency-license", metadata_path, f"{package_name} 使用 {license_text}")
            )
    return findings


def run_checks(root: Path = ROOT) -> list[Finding]:
    return [
        *check_openapi_actions(root),
        *check_python_boundaries(root),
        *check_frontend_boundaries(root),
        *check_python_licenses(root),
        *check_node_licenses(root),
    ]


def main() -> int:
    findings = run_checks(ROOT)
    if findings:
        for finding in findings:
            print(f"ERROR {finding.render(ROOT)}")
        return 1
    print("Security invariants OK: no real network client, unsafe file boundary, forbidden action, or GPL/AGPL direct dependency")
    return 0


if __name__ == "__main__":
    sys.exit(main())
