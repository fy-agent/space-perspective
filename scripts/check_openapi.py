from __future__ import annotations

from pathlib import Path
import sys

import yaml
from yaml.constructor import ConstructorError


ROOT = Path(__file__).parents[1]
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
REQUIRED_SCHEMAS = {
    "HealthResponse",
    "ScanRequest",
    "ScanSession",
    "ScanEvent",
    "Asset",
    "AssetMetadata",
    "FileIntelOverview",
    "DuplicateGroup",
    "DuplicateMember",
    "Suggestion",
    "OperationPreviewRequest",
    "OperationPlan",
    "OperationExecuteRequest",
    "OperationReceipt",
    "QuarantineItem",
    "ErrorResponse",
    "InventoryScanCreateRequest",
    "InventoryScanResponse",
    "InventorySnapshotCreateRequest",
    "ReportSnapshotV1",
    "InventoryPacketPreviewRequest",
    "InventoryPacketPreviewResponse",
    "AnalysisPacketV1",
    "CoverageSummaryV1",
    "PacketObjectV1",
    "LongTailV1",
    "InventoryAnalysisCreateRequest",
    "InventoryAnalysisResponse",
    "AIAnalysisV1",
    "ModelCallReceiptV1",
    "AnalysisBudgetV1",
    "AnalysisOfferV1",
    "AnalysisConsentV1",
    "AnalysisConsentReceiptV1",
    "InventoryReportCreateRequest",
    "InventoryReportResponse",
    "ReportManifestV1",
}
FORBIDDEN_ACTIONS = {"delete", "permanent_delete", "upload"}


class UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: UniqueKeyLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[object, object]:
    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def validate_openapi(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        document = yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
    except (OSError, yaml.YAMLError) as exc:
        return [f"OpenAPI 无法解析：{exc}"]

    paths = document.get("paths", {})
    operations = {
        (path_name, method.lower())
        for path_name, path_item in paths.items()
        for method in path_item
        if method.lower() in {"get", "post", "put", "patch", "delete"}
    }
    expected_operations = LEGACY_OPERATIONS | INVENTORY_OPERATIONS
    if operations != expected_operations:
        missing_operations = sorted(expected_operations - operations)
        extra_operations = sorted(operations - expected_operations)
        if missing_operations:
            errors.append(f"OpenAPI 缺少 operation：{missing_operations}")
        if extra_operations:
            errors.append(f"OpenAPI 包含未冻结 operation：{extra_operations}")
    if len(paths) != 28:
        errors.append(f"OpenAPI path patterns 应为 28，实际为 {len(paths)}")

    schemas = document.get("components", {}).get("schemas", {})
    missing = sorted(REQUIRED_SCHEMAS - set(schemas))
    if missing:
        errors.append(f"OpenAPI 缺少 schema：{', '.join(missing)}")

    actions = set(schemas.get("OperationAction", {}).get("enum", []))
    forbidden = sorted(actions & FORBIDDEN_ACTIONS)
    if forbidden:
        errors.append(f"OpenAPI 包含禁止动作：{', '.join(forbidden)}")

    health = schemas.get("HealthResponse", {})
    real_upload = (
        health.get("properties", {})
        .get("capabilities", {})
        .get("properties", {})
        .get("real_upload_enabled", {})
        .get("enum")
    )
    if real_upload != [False]:
        errors.append("HealthResponse 必须把 real_upload_enabled 锁定为 false")
    capability_properties = (
        health.get("properties", {})
        .get("capabilities", {})
        .get("properties", {})
    )
    for field in (
        "file_upload_enabled",
        "cloud_metadata_analysis_available",
        "cloud_metadata_analysis_enabled",
    ):
        if capability_properties.get(field, {}).get("enum") != [False]:
            errors.append(f"HealthResponse 必须把 {field} 锁定为 false")
    if (
        capability_properties.get(
            "controlled_synthetic_consent_available",
            {},
        ).get("enum")
        != [True]
    ):
        errors.append(
            "HealthResponse 必须把 controlled_synthetic_consent_available 锁定为 true"
        )

    scan_request = schemas.get("InventoryScanCreateRequest", {})
    scan_properties = scan_request.get("properties", {})
    if scan_request.get("additionalProperties") is not False:
        errors.append("InventoryScanCreateRequest 必须拒绝未知字段")
    if scan_properties.get("fixture_id", {}).get("enum") != ["standard"]:
        errors.append("Inventory scan fixture_id 必须锁定为 standard")
    if scan_properties.get("profile", {}).get("enum") != ["inventory_metadata"]:
        errors.append("Inventory scan profile 必须锁定为 inventory_metadata")
    if scan_properties.get("compute_hash", {}).get("enum") != [False]:
        errors.append("Inventory scan compute_hash 必须锁定为 false")

    provider_enum = (
        schemas.get("InventoryAnalysisCreateRequest", {})
        .get("properties", {})
        .get("provider", {})
        .get("enum")
    )
    if provider_enum != ["none", "fake"]:
        errors.append("Inventory provider 必须精确锁定为 none|fake")
    execution_enum = (
        schemas.get("InventoryPacketPreviewRequest", {})
        .get("properties", {})
        .get("analysis_execution_mode", {})
        .get("enum")
    )
    if execution_enum != [
        "none",
        "local_only",
        "cloud_metadata_minimized",
    ]:
        errors.append(
            "Inventory execution mode 必须精确锁定为 "
            "none|local_only|cloud_metadata_minimized"
        )
    budget_properties = schemas.get("AnalysisBudgetV1", {}).get("properties", {})
    if budget_properties.get("max_provider_calls", {}).get("enum") != [1]:
        errors.append("AnalysisBudgetV1 max_provider_calls 必须锁定为一次 primary call")
    if "Primary provider calls" not in budget_properties.get(
        "max_provider_calls",
        {},
    ).get("description", ""):
        errors.append("AnalysisBudgetV1 必须说明 primary call 与 schema retry 分账")
    schema_retry = budget_properties.get("max_schema_retries", {})
    if schema_retry.get("maximum") != 1 or "total attempts are at most two" not in (
        schema_retry.get("description", "")
    ):
        errors.append("AnalysisBudgetV1 必须把 schema retry 与总 attempts 锁定为 1/2")
    if budget_properties.get("max_estimated_cost", {}).get("enum") != [0]:
        errors.append("AnalysisBudgetV1 synthetic cost 上限必须锁定为 0")
    if "Cooperative wall-clock deadline" not in budget_properties.get(
        "timeout_ms",
        {},
    ).get("description", ""):
        errors.append("AnalysisBudgetV1 timeout 必须明确为 offline fake cooperative deadline")

    consent_properties = schemas.get("AnalysisConsentV1", {}).get("properties", {})
    if not consent_properties.get("consent_receipt_id", {}).get(
        "pattern",
        "",
    ).startswith("^consent_receipt_"):
        errors.append("AnalysisConsentV1 consent_receipt_id 必须锁定 UUID 前缀形态")
    if not consent_properties.get("client_action_id", {}).get(
        "pattern",
        "",
    ).startswith("^client_action_"):
        errors.append("AnalysisConsentV1 client_action_id 必须锁定 UUID 前缀形态")

    consent_receipt_required = set(
        schemas.get("AnalysisConsentReceiptV1", {}).get("required", [])
    )
    required_receipt_audit = {
        "synthetic",
        "provider_calls",
        "network_calls",
        "input_tokens",
        "cached_input_tokens",
        "output_tokens",
        "estimated_cost",
        "latency_ms",
        "fallback",
    }
    if not required_receipt_audit <= consent_receipt_required:
        errors.append("AnalysisConsentReceiptV1 缺少冻结的实际用量或 fallback 字段")

    download = paths.get("/v1/inventory/reports/{report_id}/download", {}).get("get", {})
    download_response = download.get("responses", {}).get("200", {})
    if (
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        not in download_response.get("content", {})
    ):
        errors.append("Inventory report download 必须声明 XLSX media type")
    cache_control = (
        download_response.get("headers", {})
        .get("Cache-Control", {})
        .get("schema", {})
        .get("enum")
    )
    if cache_control != ["no-store"]:
        errors.append("Inventory report download 必须锁定 Cache-Control: no-store")
    return errors


def main() -> int:
    errors = validate_openapi(ROOT / "shared" / "openapi.yaml")
    if errors:
        for error in errors:
            print(f"ERROR {error}")
        return 1
    print(
        "OpenAPI OK: 18 legacy + 10 additive operations, "
        "required schemas present, fixture/provider/safety boundaries locked"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
