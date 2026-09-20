from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).parents[1]


@dataclass(frozen=True, slots=True)
class Check:
    name: str
    command: tuple[str, ...]
    cwd: Path = ROOT


def main() -> int:
    npm = "npm.cmd" if os.name == "nt" else "npm"
    checks = (
        Check("Python tests", (sys.executable, "-m", "pytest", "-q")),
        Check("OpenAPI contract", (sys.executable, "scripts/check_openapi.py")),
        Check("Security invariants", (sys.executable, "scripts/security_check.py")),
        Check("P0 smoke", (sys.executable, "scripts/smoke_test.py")),
        Check("UI tests", (npm, "test"), ROOT / "ui"),
        Check("UI build", (npm, "run", "build"), ROOT / "ui"),
    )
    for check in checks:
        print(f"\n== {check.name} ==", flush=True)
        result = subprocess.run(check.command, cwd=check.cwd, check=False)
        if result.returncode != 0:
            print(f"FAILED: {check.name}")
            return result.returncode
    print("\nAll P0 checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
