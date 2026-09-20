from pathlib import Path

from fastapi.testclient import TestClient
import yaml

from core.app.config import Settings
from core.app.main import create_app
from scripts.check_openapi import validate_openapi

ROOT = Path(__file__).parents[2]
LEGACY_OPERATIONS = {
    ("/health", "get"),
    ("/scan", "post"),
    ("/scan/{scan_session_id}", "get"),
    ("/scan/{scan_session_id}/stream", "get"),
    ("/scan/{scan_session_id}/cancel", "post"),
    ("/assets", "get"),
    ("/assets/{asset_id}", "get"),
    ("/fileintel/overview", "get"),
    ("/dups", "get"),
    ("/suggestions", "get"),
    ("/operations/preview", "post"),
    ("/operations/execute", "post"),
    ("/operations", "get"),
    ("/operations/{operation_id}", "get"),
    ("/operations/{operation_id}/undo", "post"),
    ("/quarantine", "get"),
    ("/providers", "get"),
    ("/providers/mock/analyze", "post"),
}
INVENTORY_OPERATIONS = {
    ("/v1/inventory/scans", "post"),
    ("/v1/inventory/scans/{scan_id}", "get"),
    ("/v1/inventory/snapshots", "post"),
    ("/v1/inventory/snapshots/{snapshot_id}", "get"),
    ("/v1/inventory/analysis-packets/preview", "post"),
    ("/v1/inventory/analyses", "post"),
    ("/v1/inventory/analyses/{analysis_id}", "get"),
    ("/v1/inventory/reports", "post"),
    ("/v1/inventory/reports/{report_id}", "get"),
    ("/v1/inventory/reports/{report_id}/download", "get"),
}


def _operations(document: dict) -> set[tuple[str, str]]:
    return {
        (path, method.lower())
        for path, operations in document["paths"].items()
        for method in operations
        if method.lower() in {"get", "post", "put", "patch", "delete"}
    }


def test_health_contract_keeps_required_safety_fields() -> None:
    document = yaml.safe_load((ROOT / "shared" / "openapi.yaml").read_text(encoding="utf-8"))
    health = document["components"]["schemas"]["HealthResponse"]

    assert set(health["required"]) == {
        "status",
        "version",
        "db_status",
        "capabilities",
        "current_time",
    }
    real_upload = health["properties"]["capabilities"]["properties"]["real_upload_enabled"]
    assert real_upload["enum"] == [False]
    capability_properties = health["properties"]["capabilities"]["properties"]
    assert capability_properties["file_upload_enabled"]["enum"] == [False]
    assert capability_properties["cloud_metadata_analysis_available"]["enum"] == [False]
    assert capability_properties["cloud_metadata_analysis_enabled"]["enum"] == [False]


def test_inventory_operations_are_exactly_additive_and_fixture_only() -> None:
    document = yaml.safe_load((ROOT / "shared" / "openapi.yaml").read_text(encoding="utf-8"))
    actual = _operations(document)
    assert actual == LEGACY_OPERATIONS | INVENTORY_OPERATIONS
    assert len(actual) == 28

    schemas = document["components"]["schemas"]
    scan = schemas["InventoryScanCreateRequest"]
    assert scan["additionalProperties"] is False
    assert scan["properties"]["fixture_id"]["enum"] == ["standard"]
    assert scan["properties"]["profile"]["enum"] == ["inventory_metadata"]
    assert scan["properties"]["compute_hash"]["enum"] == [False]
    assert schemas["InventoryAnalysisCreateRequest"]["properties"]["provider"]["enum"] == [
        "none",
        "fake",
    ]
    assert schemas["InventoryPacketPreviewRequest"]["properties"][
        "analysis_execution_mode"
    ]["enum"] == ["none", "local_only", "cloud_metadata_minimized"]
    budget = schemas["AnalysisBudgetV1"]["properties"]
    assert "Primary provider calls" in budget["max_provider_calls"]["description"]
    assert "total attempts are at most two" in budget["max_schema_retries"][
        "description"
    ]
    assert "Cooperative wall-clock deadline" in budget["timeout_ms"]["description"]
    consent_properties = schemas["AnalysisConsentV1"]["properties"]
    assert consent_properties["consent_receipt_id"]["pattern"].startswith(
        "^consent_receipt_"
    )
    assert consent_properties["client_action_id"]["pattern"].startswith(
        "^client_action_"
    )
    assert {
        "synthetic",
        "provider_calls",
        "network_calls",
        "input_tokens",
        "cached_input_tokens",
        "output_tokens",
        "estimated_cost",
        "latency_ms",
        "fallback",
    } <= set(schemas["AnalysisConsentReceiptV1"]["required"])


def test_runtime_implements_every_frozen_openapi_operation(settings: Settings) -> None:
    contract = yaml.safe_load((ROOT / "shared" / "openapi.yaml").read_text(encoding="utf-8"))
    expected = _operations(contract)
    with TestClient(create_app(settings)) as client:
        runtime = client.app.openapi()
    actual = _operations(runtime)
    assert actual == expected


def test_inventory_runtime_matches_canonical_contract_projection(settings: Settings) -> None:
    contract = yaml.safe_load((ROOT / "shared" / "openapi.yaml").read_text(encoding="utf-8"))
    with TestClient(create_app(settings)) as client:
        runtime = client.app.openapi()

    for path, method in INVENTORY_OPERATIONS:
        expected = contract["paths"][path][method]
        actual = runtime["paths"][path][method]
        assert actual["operationId"] == expected["operationId"]

        expected_body = expected.get("requestBody")
        actual_body = actual.get("requestBody")
        if expected_body is None:
            assert actual_body is None
        else:
            assert actual_body["content"]["application/json"]["schema"] == expected_body[
                "content"
            ]["application/json"]["schema"]

        assert actual["responses"]["default"]["content"]["application/json"]["schema"] == {
            "$ref": "#/components/schemas/ErrorResponse"
        }
        success_code = next(code for code in expected["responses"] if code != "default")
        if path.endswith("/download"):
            assert actual["responses"][success_code]["content"] == expected["responses"][
                success_code
            ]["content"]
            assert actual["responses"][success_code]["headers"] == expected["responses"][
                success_code
            ]["headers"]
        else:
            expected_schema = expected["responses"][success_code]["content"][
                "application/json"
            ]["schema"]
            actual_schema = actual["responses"][success_code]["content"][
                "application/json"
            ]["schema"]
            assert actual_schema == expected_schema

    for schema_name in (
        "InventoryScanCreateRequest",
        "AnalysisPacketV1",
        "CoverageSummaryV1",
        "PacketObjectV1",
        "LongTailV1",
        "AnalysisBudgetV1",
        "AnalysisConsentReceiptV1",
        "AIAnalysisV1",
        "ModelCallReceiptV1",
    ):
        expected_schema = contract["components"]["schemas"][schema_name]
        actual_schema = runtime["components"]["schemas"][schema_name]
        assert actual_schema["additionalProperties"] is False
        assert expected_schema["additionalProperties"] is False
        assert set(actual_schema["properties"]) == set(expected_schema["properties"])
        assert set(actual_schema.get("required", [])) == set(
            expected_schema.get("required", [])
        )


def test_openapi_validator_rejects_duplicate_yaml_keys(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.yaml"
    duplicate.write_text(
        "openapi: 3.0.3\npaths:\n  /health:\n    get: {}\n    get: {}\n",
        encoding="utf-8",
    )
    errors = validate_openapi(duplicate)
    assert len(errors) == 1
    assert "duplicate key" in errors[0]
