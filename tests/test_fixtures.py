from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

from fixtures.generate import generate


def _tree_hashes(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def test_fixture_generation_is_idempotent_and_records_duplicates(tmp_path: Path) -> None:
    target = tmp_path / "demo-corpus"
    first_manifest = generate(target)
    first_hashes = _tree_hashes(target)
    second_manifest = generate(target)

    assert second_manifest == first_manifest
    assert _tree_hashes(target) == first_hashes
    duplicate_paths = first_manifest["expected_exact_duplicate_groups"][0]
    assert (target / duplicate_paths[0]).read_bytes() == (target / duplicate_paths[1]).read_bytes()

    persisted = json.loads((target / "manifest.json").read_text(encoding="utf-8"))
    assert persisted["fixture_kind"] == "artificial_non_sensitive"


def test_risk_named_samples_contain_no_identity_or_payment_numbers(tmp_path: Path) -> None:
    target = tmp_path / "demo-corpus"
    generate(target)

    combined = "\n".join(
        path.read_text(encoding="utf-8", errors="ignore")
        for path in target.rglob("*")
        if path.is_file()
    )
    assert not re.search(r"\b\d{16,19}\b", combined)
    assert not re.search(r"\b\d{17}[0-9Xx]\b", combined)
    assert "artificial_non_sensitive" in combined
