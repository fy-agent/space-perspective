from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator
import pytest
from pydantic import ValidationError

from core.analysis.schemas import AIFindingV1
from core.inventory.models import ScanFactV1, TimeEvidenceV1


ROOT = Path(__file__).parents[2]
SCHEMA_ROOT = ROOT / "shared" / "schemas"


def _assert_strict_objects(value: object) -> None:
    if isinstance(value, dict):
        if value.get("type") == "object":
            assert value.get("additionalProperties") is False
        for nested in value.values():
            _assert_strict_objects(nested)
    elif isinstance(value, list):
        for nested in value:
            _assert_strict_objects(nested)


def test_all_seven_json_schemas_are_versioned_and_strict() -> None:
    paths = sorted(SCHEMA_ROOT.glob("*-v1.schema.json"))
    assert len(paths) == 7
    for path in paths:
        document = json.loads(path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(document)
        version_field = (
            "consent_schema_version"
            if path.name == "analysis-consent-v1.schema.json"
            else "schema_version"
        )
        assert document["properties"][version_field]["const"] == "1.0"
        if path.name == "analysis-consent-v1.schema.json":
            assert document["properties"]["consent_receipt_id"]["pattern"].startswith(
                "^consent_receipt_"
            )
            assert document["properties"]["client_action_id"]["pattern"].startswith(
                "^client_action_"
            )
            budget = document["$defs"]["AnalysisBudgetV1"]["properties"]
            assert "Primary provider calls" in budget["max_provider_calls"]["description"]
            assert "total attempts are at most two" in budget["max_schema_retries"][
                "description"
            ]
            assert "Cooperative wall-clock deadline" in budget["timeout_ms"][
                "description"
            ]
        _assert_strict_objects(document)


def _time() -> TimeEvidenceV1:
    return TimeEvidenceV1(
        value=None,
        source="unavailable",
        evidence_type="unavailable",
        confidence="unknown",
        platform="macos",
        limitation="unknown",
    )


def test_schema_models_reject_negative_bytes_and_unknown_fields() -> None:
    common = {
        "fact_id": "fact_1",
        "scope_id": "fixture",
        "relative_path": "sample.txt",
        "absolute_path": "/fixture/sample.txt",
        "name": "sample.txt",
        "parent_relative_path": None,
        "file_type": "file",
        "status": "collected",
        "logical_size_bytes": 1,
        "allocated_size_bytes": 1,
        "extension": ".txt",
        "modified": _time(),
        "created": _time(),
        "accessed": _time(),
        "platform": "macos",
    }
    negative = {**common, "logical_size_bytes": -1}
    with pytest.raises(ValidationError):
        ScanFactV1(**negative)
    with pytest.raises(ValidationError):
        ScanFactV1(**common, unexpected=True)
    with pytest.raises(ValidationError):
        AIFindingV1(
            finding_id="f",
            object_ids=["o"],
            evidence_ids=["e"],
            observation="x",
            recommendation="delete",
        )
