from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import sqlite3
from threading import Barrier
from time import perf_counter

from fastapi.testclient import TestClient
import pytest

from core.app.config import Settings
from core.app.main import create_app
from core.analysis.schemas import AnalysisConsentV1
from core.inventory.models import canonical_json


CONSENT_ID_1 = "consent_receipt_00000000-0000-4000-8000-000000000001"
ACTION_ID_1 = "client_action_00000000-0000-4000-8000-000000000001"
CONSENT_ID_2 = "consent_receipt_00000000-0000-4000-8000-000000000002"
ACTION_ID_2 = "client_action_00000000-0000-4000-8000-000000000002"
ACTION_ID_3 = "client_action_00000000-0000-4000-8000-000000000003"


def _preview_synthetic(
    client: TestClient,
    *,
    max_input_tokens: int = 12_000,
    max_output_tokens: int = 2_500,
    top_k: int = 200,
) -> dict[str, object]:
    scan = client.post(
        "/v1/inventory/scans",
        json={
            "fixture_id": "standard",
            "profile": "inventory_metadata",
            "compute_hash": False,
        },
    )
    assert scan.status_code == 201, scan.text
    snapshot_id = scan.json()["snapshot_id"]
    response = client.post(
        "/v1/inventory/analysis-packets/preview",
        json={
            "snapshot_id": snapshot_id,
            "artifact_privacy_mode": "share_safe",
            "analysis_execution_mode": "cloud_metadata_minimized",
            "top_k": top_k,
            "budget": {
                "max_provider_calls": 1,
                "max_schema_retries": 1,
                "max_input_tokens": max_input_tokens,
                "max_output_tokens": max_output_tokens,
                "max_packet_bytes": 256_000,
                "timeout_ms": 90_000,
                "max_estimated_cost": 0,
            },
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def _consent(offer: dict[str, object]) -> dict[str, object]:
    return {
        "consent_receipt_id": CONSENT_ID_1,
        "client_action_id": ACTION_ID_1,
        "confirmed": True,
        "snapshot_id": offer["snapshot_id"],
        "snapshot_sha256": offer["snapshot_sha256"],
        "packet_id": offer["packet_id"],
        "packet_sha256": offer["packet_sha256"],
        "packet_bytes": offer["packet_bytes"],
        "artifact_privacy_mode": "share_safe",
        "analysis_execution_mode": "cloud_metadata_minimized",
        "provider": offer["provider"],
        "model": offer["model"],
        "prompt_version": offer["prompt_version"],
        "consent_schema_version": offer["consent_schema_version"],
        "analysis_schema_version": offer["analysis_schema_version"],
        "disclosure_version": offer["disclosure_version"],
        "budget": offer["budget"],
        "cost_basis": offer["cost_basis"],
    }


def test_preview_discloses_offline_synthetic_offer(settings: Settings) -> None:
    with TestClient(create_app(settings)) as client:
        preview = _preview_synthetic(client)

    offer = preview["analysis_offer"]
    assert offer["synthetic"] is True
    assert offer["consent_required"] is True
    assert offer["network_calls"] == 0
    assert offer["provider"] == "fake"
    assert offer["model"] == "fixture-analyst-v1"
    assert offer["packet_id"] == preview["packet"]["packet_id"]
    assert offer["packet_sha256"] == preview["packet"]["packet_sha256"]
    assert offer["packet_bytes"] == preview["privacy_lint"]["packet_bytes"]
    assert offer["estimated_input_tokens"] == preview["estimated_input_tokens"]
    assert offer["estimated_output_tokens"] > 0
    assert offer["budget"]["max_estimated_cost"] == 0
    assert offer["cost_basis"] == "synthetic_zero_external_cost"
    assert "file_content" in offer["excluded_field_categories"]


def test_synthetic_consent_success_and_same_action_retry_are_idempotent(
    settings: Settings,
) -> None:
    with TestClient(create_app(settings)) as client:
        preview = _preview_synthetic(client)
        offer = preview["analysis_offer"]
        body = {
            "packet_id": preview["packet"]["packet_id"],
            "provider": "fake",
            "consent": _consent(offer),
        }

        first = client.post("/v1/inventory/analyses", json=body)
        repeated = client.post("/v1/inventory/analyses", json=body)

        assert first.status_code == 201, first.text
        assert repeated.status_code == 201, repeated.text
        assert repeated.json() == first.json()
        payload = first.json()
        assert payload["analysis"]["status"] == "ai_complete"
        assert payload["receipt"]["provider_calls"] == 1
        assert payload["receipt"]["network_calls"] == 0
        assert payload["receipt"]["consent_status"] == "consumed"
        assert payload["receipt"]["consent_receipt_id"] == CONSENT_ID_1
        assert payload["consent_receipt"]["status"] == "consumed"
        assert payload["consent_receipt"]["network_calls"] == 0
        assert payload["consent_receipt"]["input_tokens"] == payload["receipt"]["input_tokens"]
        assert payload["consent_receipt"]["cached_input_tokens"] == 0
        assert payload["consent_receipt"]["output_tokens"] == payload["receipt"]["output_tokens"]
        assert payload["consent_receipt"]["estimated_cost"] == 0
        assert payload["consent_receipt"]["latency_ms"] == payload["receipt"]["latency_ms"]
        assert payload["consent_receipt"]["fallback"] is False
        assert client.app.state.inventory_service.fake_provider.calls == 1


def test_stale_identifier_read_replays_cross_service_completed_action(
    settings: Settings,
) -> None:
    body: dict[str, object]
    with TestClient(create_app(settings)) as first_client:
        preview = _preview_synthetic(first_client)
        body = {
            "packet_id": preview["packet"]["packet_id"],
            "provider": "fake",
            "consent": _consent(preview["analysis_offer"]),
        }
        first = first_client.post("/v1/inventory/analyses", json=body)
        assert first.status_code == 201, first.text
        first_payload = first.json()
        assert first_client.app.state.inventory_service.fake_provider.calls == 1

    with TestClient(create_app(settings)) as second_client:
        second_client.app.state.repository.analysis_consent_identifier_exists = (
            lambda **_: False
        )
        replay = second_client.post("/v1/inventory/analyses", json=body)

        assert replay.status_code == 201, replay.text
        assert replay.json() == first_payload
        assert second_client.app.state.inventory_service.fake_provider.calls == 0


def test_concurrent_cross_service_consents_keep_distinct_lineage(
    settings: Settings,
) -> None:
    with (
        TestClient(create_app(settings)) as first_client,
        TestClient(create_app(settings)) as second_client,
    ):
        preview = _preview_synthetic(first_client)
        first_consent = _consent(preview["analysis_offer"])
        second_consent = {
            **first_consent,
            "consent_receipt_id": CONSENT_ID_2,
            "client_action_id": ACTION_ID_2,
        }
        barrier = Barrier(2)

        def gate_provider(provider: object) -> None:
            original_analyze = provider.analyze

            def analyze(packet: object, *, timeout_ms: int | None = None):
                barrier.wait(timeout=2)
                return original_analyze(packet, timeout_ms=timeout_ms)

            provider.analyze = analyze

        first_provider = first_client.app.state.inventory_service.fake_provider
        second_provider = second_client.app.state.inventory_service.fake_provider
        gate_provider(first_provider)
        gate_provider(second_provider)

        first_body = {
            "packet_id": preview["packet"]["packet_id"],
            "provider": "fake",
            "consent": first_consent,
        }
        second_body = {
            "packet_id": preview["packet"]["packet_id"],
            "provider": "fake",
            "consent": second_consent,
        }
        with ThreadPoolExecutor(max_workers=2) as pool:
            first_future = pool.submit(
                first_client.post,
                "/v1/inventory/analyses",
                json=first_body,
            )
            second_future = pool.submit(
                second_client.post,
                "/v1/inventory/analyses",
                json=second_body,
            )
            first_response = first_future.result()
            second_response = second_future.result()

        assert first_response.status_code == 201, first_response.text
        assert second_response.status_code == 201, second_response.text
        first_payload = first_response.json()
        second_payload = second_response.json()
        first_analysis_id = first_payload["analysis"]["analysis_id"]
        second_analysis_id = second_payload["analysis"]["analysis_id"]
        assert first_analysis_id != second_analysis_id
        assert first_payload["receipt"]["status"] == "succeeded"
        assert second_payload["receipt"]["status"] == "succeeded"
        assert first_payload["receipt"]["provider_calls"] == 1
        assert second_payload["receipt"]["provider_calls"] == 1
        assert first_provider.calls == 1
        assert second_provider.calls == 1

        first_get = first_client.get(
            f"/v1/inventory/analyses/{first_analysis_id}"
        )
        second_get = first_client.get(
            f"/v1/inventory/analyses/{second_analysis_id}"
        )
        assert first_get.status_code == 200, first_get.text
        assert second_get.status_code == 200, second_get.text
        assert (
            first_get.json()["receipt"]["consent_receipt_id"]
            == CONSENT_ID_1
        )
        assert (
            first_get.json()["consent_receipt"]["consent_receipt_id"]
            == CONSENT_ID_1
        )
        assert (
            second_get.json()["receipt"]["consent_receipt_id"]
            == CONSENT_ID_2
        )
        assert (
            second_get.json()["consent_receipt"]["consent_receipt_id"]
            == CONSENT_ID_2
        )

        first_cached_base = next(
            iter(first_client.app.state.inventory_service.analysis_cache.values.values())
        )
        second_cached_base = next(
            iter(second_client.app.state.inventory_service.analysis_cache.values.values())
        )
        assert first_cached_base.analysis_id == second_cached_base.analysis_id
        assert first_cached_base.analysis_id not in {
            first_analysis_id,
            second_analysis_id,
        }


def test_new_consent_for_same_packet_hits_product_cache(settings: Settings) -> None:
    with TestClient(create_app(settings)) as client:
        preview = _preview_synthetic(client)
        offer = preview["analysis_offer"]
        first_consent = _consent(offer)
        second_consent = {
            **first_consent,
            "consent_receipt_id": CONSENT_ID_2,
            "client_action_id": ACTION_ID_2,
        }

        first = client.post(
            "/v1/inventory/analyses",
            json={
                "packet_id": preview["packet"]["packet_id"],
                "provider": "fake",
                "consent": first_consent,
            },
        )
        cached = client.post(
            "/v1/inventory/analyses",
            json={
                "packet_id": preview["packet"]["packet_id"],
                "provider": "fake",
                "consent": second_consent,
            },
        )

        assert first.status_code == 201
        assert cached.status_code == 201
        assert cached.json()["receipt"]["status"] == "cache_hit"
        assert cached.json()["receipt"]["provider_calls"] == 0
        assert cached.json()["receipt"]["cached_input_tokens"] == 0
        assert cached.json()["receipt"]["consent_receipt_id"] == CONSENT_ID_2
        assert cached.json()["consent_receipt"]["input_tokens"] == 0
        assert cached.json()["consent_receipt"]["cached_input_tokens"] == 0
        assert cached.json()["consent_receipt"]["output_tokens"] == 0
        assert cached.json()["consent_receipt"]["fallback"] is False
        assert client.app.state.inventory_service.fake_provider.calls == 1


def test_missing_or_mismatched_consent_is_blocked_before_provider(
    settings: Settings,
) -> None:
    with TestClient(create_app(settings)) as client:
        preview = _preview_synthetic(client)
        packet_id = preview["packet"]["packet_id"]
        missing = client.post(
            "/v1/inventory/analyses",
            json={"packet_id": packet_id, "provider": "fake"},
        )
        bad = _consent(preview["analysis_offer"])
        bad["packet_sha256"] = "f" * 64
        mismatched = client.post(
            "/v1/inventory/analyses",
            json={"packet_id": packet_id, "provider": "fake", "consent": bad},
        )

        assert missing.status_code == 409
        assert missing.json()["code"] == "ANALYSIS_CONSENT_REQUIRED"
        assert mismatched.status_code == 409
        assert mismatched.json()["code"] == "ANALYSIS_CONSENT_MISMATCH"
        assert client.app.state.inventory_service.fake_provider.calls == 0


def test_synthetic_timeout_falls_back_without_network(settings: Settings) -> None:
    with TestClient(create_app(settings)) as client:
        preview = _preview_synthetic(client)
        offer = preview["analysis_offer"]
        offer["budget"]["timeout_ms"] = 5
        consent = _consent(offer)
        client.app.state.inventory_service.fake_provider.latency_ms = 500

        started = perf_counter()
        response = client.post(
            "/v1/inventory/analyses",
            json={
                "packet_id": preview["packet"]["packet_id"],
                "provider": "fake",
                "consent": consent,
            },
        )
        elapsed = perf_counter() - started

        assert response.status_code == 201
        receipt = response.json()["receipt"]
        assert receipt["status"] == "provider_failed"
        assert receipt["error_code"] == "SYNTHETIC_TIMEOUT"
        assert receipt["provider_calls"] == 1
        assert receipt["network_calls"] == 0
        assert receipt["fallback"] is True
        assert elapsed < 0.2


def test_schema_retry_uses_one_aggregate_timeout_budget(
    settings: Settings,
) -> None:
    with TestClient(create_app(settings)) as client:
        preview = _preview_synthetic(client)
        consent = _consent(preview["analysis_offer"])
        consent["budget"]["timeout_ms"] = 100
        fake_provider = client.app.state.inventory_service.fake_provider
        fake_provider.latency_ms = 60
        fake_provider.schema_failures = 1

        started = perf_counter()
        response = client.post(
            "/v1/inventory/analyses",
            json={
                "packet_id": preview["packet"]["packet_id"],
                "provider": "fake",
                "consent": consent,
            },
        )
        elapsed = perf_counter() - started

        assert response.status_code == 201, response.text
        receipt = response.json()["receipt"]
        assert receipt["status"] == "provider_failed"
        assert receipt["error_code"] == "SYNTHETIC_TIMEOUT"
        assert receipt["provider_calls"] == 2
        assert receipt["input_tokens"] == preview["estimated_input_tokens"]
        assert receipt["output_tokens"] > 0
        assert receipt["latency_ms"] >= 90
        assert receipt["network_calls"] == 0
        assert fake_provider.calls == 2
        assert elapsed < 0.2


def test_synthetic_fake_latency_is_executed_within_budget(settings: Settings) -> None:
    with TestClient(create_app(settings)) as client:
        preview = _preview_synthetic(client)
        client.app.state.inventory_service.fake_provider.latency_ms = 30

        started = perf_counter()
        response = client.post(
            "/v1/inventory/analyses",
            json={
                "packet_id": preview["packet"]["packet_id"],
                "provider": "fake",
                "consent": _consent(preview["analysis_offer"]),
            },
        )
        elapsed = perf_counter() - started

        assert response.status_code == 201
        assert response.json()["receipt"]["status"] == "succeeded"
        assert response.json()["receipt"]["latency_ms"] >= 30
        assert elapsed >= 0.02


def test_schema_retry_is_bounded_and_remains_offline(settings: Settings) -> None:
    with TestClient(create_app(settings)) as client:
        preview = _preview_synthetic(client)
        client.app.state.inventory_service.fake_provider.schema_failures = 1
        response = client.post(
            "/v1/inventory/analyses",
            json={
                "packet_id": preview["packet"]["packet_id"],
                "provider": "fake",
                "consent": _consent(preview["analysis_offer"]),
            },
        )

        assert response.status_code == 201
        payload = response.json()
        receipt = payload["receipt"]
        schema_output_tokens = max(
            1,
            len(
                canonical_json(
                    {
                        "controlled_schema_error": True,
                        "packet_id": preview["packet"]["packet_id"],
                    }
                ).encode("utf-8")
            )
            // 4,
        )
        success_output_tokens = max(
            1,
            len(canonical_json(payload["analysis"]).encode("utf-8")) // 4,
        )
        assert (
            success_output_tokens
            == preview["analysis_offer"]["estimated_output_tokens"]
        )
        assert receipt["status"] == "succeeded"
        assert receipt["provider_calls"] == 2
        assert receipt["network_calls"] == 0
        assert receipt["input_tokens"] == preview["estimated_input_tokens"] * 2
        assert receipt["cached_input_tokens"] == 0
        assert receipt["output_tokens"] == (
            schema_output_tokens + success_output_tokens
        )
        assert receipt["latency_ms"] == 2
        assert payload["consent_receipt"]["input_tokens"] == receipt["input_tokens"]
        assert payload["consent_receipt"]["output_tokens"] == receipt["output_tokens"]
        assert payload["consent_receipt"]["latency_ms"] == receipt["latency_ms"]

        exhausted_preview = _preview_synthetic(client, top_k=1)
        exhausted_consent = _consent(exhausted_preview["analysis_offer"])
        exhausted_consent["consent_receipt_id"] = CONSENT_ID_2
        exhausted_consent["client_action_id"] = ACTION_ID_2
        client.app.state.inventory_service.fake_provider.schema_failures = 2
        exhausted = client.post(
            "/v1/inventory/analyses",
            json={
                "packet_id": exhausted_preview["packet"]["packet_id"],
                "provider": "fake",
                "consent": exhausted_consent,
            },
        )
        assert exhausted.status_code == 201
        exhausted_payload = exhausted.json()
        exhausted_receipt = exhausted_payload["receipt"]
        exhausted_schema_output = max(
            1,
            len(
                canonical_json(
                    {
                        "controlled_schema_error": True,
                        "packet_id": exhausted_preview["packet"]["packet_id"],
                    }
                ).encode("utf-8")
            )
            // 4,
        )
        assert exhausted_receipt["status"] == "schema_failed"
        assert exhausted_receipt["provider_calls"] == 2
        assert exhausted_receipt["input_tokens"] == (
            exhausted_preview["estimated_input_tokens"] * 2
        )
        assert exhausted_receipt["output_tokens"] == exhausted_schema_output * 2
        assert exhausted_receipt["latency_ms"] == 2
        assert exhausted_payload["consent_receipt"]["input_tokens"] == (
            exhausted_receipt["input_tokens"]
        )
        assert exhausted_payload["consent_receipt"]["output_tokens"] == (
            exhausted_receipt["output_tokens"]
        )
        assert exhausted_payload["consent_receipt"]["latency_ms"] == (
            exhausted_receipt["latency_ms"]
        )


def test_schema_retry_respects_cumulative_input_budget(settings: Settings) -> None:
    with TestClient(create_app(settings)) as client:
        baseline = _preview_synthetic(client, top_k=1)
        cumulative_limit = int(baseline["estimated_input_tokens"]) + 1
        preview = _preview_synthetic(
            client,
            top_k=1,
            max_input_tokens=cumulative_limit,
        )
        client.app.state.inventory_service.fake_provider.schema_failures = 1
        response = client.post(
            "/v1/inventory/analyses",
            json={
                "packet_id": preview["packet"]["packet_id"],
                "provider": "fake",
                "consent": _consent(preview["analysis_offer"]),
            },
        )

        assert response.status_code == 201
        receipt = response.json()["receipt"]
        assert receipt["status"] == "budget_blocked"
        assert receipt["error_code"] == "ACTUAL_TOKEN_BUDGET_EXCEEDED"
        assert receipt["provider_calls"] == 1
        assert receipt["input_tokens"] == preview["estimated_input_tokens"]
        assert receipt["output_tokens"] > 0
        assert client.app.state.inventory_service.fake_provider.calls == 1


def test_schema_retry_respects_remaining_output_budget(settings: Settings) -> None:
    with TestClient(create_app(settings)) as client:
        baseline = _preview_synthetic(client, top_k=1)
        exact_success_output = int(
            baseline["analysis_offer"]["estimated_output_tokens"]
        )
        preview = _preview_synthetic(
            client,
            top_k=1,
            max_output_tokens=exact_success_output,
        )
        client.app.state.inventory_service.fake_provider.schema_failures = 1
        response = client.post(
            "/v1/inventory/analyses",
            json={
                "packet_id": preview["packet"]["packet_id"],
                "provider": "fake",
                "consent": _consent(preview["analysis_offer"]),
            },
        )

        assert response.status_code == 201, response.text
        receipt = response.json()["receipt"]
        assert receipt["status"] == "budget_blocked"
        assert receipt["error_code"] == "ACTUAL_TOKEN_BUDGET_EXCEEDED"
        assert receipt["provider_calls"] == 1
        assert receipt["input_tokens"] == preview["estimated_input_tokens"]
        assert 0 < receipt["output_tokens"] < exact_success_output
        assert client.app.state.inventory_service.fake_provider.calls == 1


def test_fake_provider_failure_records_exact_usage(settings: Settings) -> None:
    with TestClient(create_app(settings)) as client:
        preview = _preview_synthetic(client)
        client.app.state.inventory_service.fake_provider.fail = True
        response = client.post(
            "/v1/inventory/analyses",
            json={
                "packet_id": preview["packet"]["packet_id"],
                "provider": "fake",
                "consent": _consent(preview["analysis_offer"]),
            },
        )

        assert response.status_code == 201, response.text
        payload = response.json()
        receipt = payload["receipt"]
        assert receipt["status"] == "provider_failed"
        assert receipt["error_code"] == "FAKE_PROVIDER_FAILED"
        assert receipt["provider_calls"] == 1
        assert receipt["input_tokens"] == preview["estimated_input_tokens"]
        assert receipt["cached_input_tokens"] == 0
        assert receipt["output_tokens"] == 0
        assert receipt["latency_ms"] == 1
        assert payload["consent_receipt"]["input_tokens"] == receipt["input_tokens"]
        assert payload["consent_receipt"]["output_tokens"] == 0
        assert payload["consent_receipt"]["latency_ms"] == receipt["latency_ms"]


def test_schema_retry_then_provider_failure_aggregates_exact_usage(
    settings: Settings,
) -> None:
    with TestClient(create_app(settings)) as client:
        preview = _preview_synthetic(client)
        fake_provider = client.app.state.inventory_service.fake_provider
        fake_provider.schema_failures = 1
        fake_provider.fail = True
        response = client.post(
            "/v1/inventory/analyses",
            json={
                "packet_id": preview["packet"]["packet_id"],
                "provider": "fake",
                "consent": _consent(preview["analysis_offer"]),
            },
        )

        assert response.status_code == 201, response.text
        payload = response.json()
        receipt = payload["receipt"]
        schema_output_tokens = max(
            1,
            len(
                canonical_json(
                    {
                        "controlled_schema_error": True,
                        "packet_id": preview["packet"]["packet_id"],
                    }
                ).encode("utf-8")
            )
            // 4,
        )
        assert receipt["status"] == "provider_failed"
        assert receipt["error_code"] == "FAKE_PROVIDER_FAILED"
        assert receipt["provider_calls"] == 2
        assert receipt["input_tokens"] == preview["estimated_input_tokens"] * 2
        assert receipt["cached_input_tokens"] == 0
        assert receipt["output_tokens"] == schema_output_tokens
        assert receipt["latency_ms"] == 2
        assert payload["consent_receipt"]["input_tokens"] == receipt["input_tokens"]
        assert payload["consent_receipt"]["output_tokens"] == receipt["output_tokens"]
        assert payload["consent_receipt"]["latency_ms"] == receipt["latency_ms"]


def test_grounding_fallback_preserves_usage_in_both_receipts(
    settings: Settings,
) -> None:
    with TestClient(create_app(settings)) as client:
        preview = _preview_synthetic(client)
        client.app.state.inventory_service.fake_provider.dangling_reference = True
        response = client.post(
            "/v1/inventory/analyses",
            json={
                "packet_id": preview["packet"]["packet_id"],
                "provider": "fake",
                "consent": _consent(preview["analysis_offer"]),
            },
        )

        assert response.status_code == 201
        model_receipt = response.json()["receipt"]
        consent_receipt = response.json()["consent_receipt"]
        assert model_receipt["status"] == "grounding_failed"
        assert model_receipt["input_tokens"] > 0
        assert model_receipt["output_tokens"] > 0
        assert model_receipt["latency_ms"] > 0
        assert consent_receipt["input_tokens"] == model_receipt["input_tokens"]
        assert consent_receipt["output_tokens"] == model_receipt["output_tokens"]
        assert consent_receipt["latency_ms"] == model_receipt["latency_ms"]
        assert consent_receipt["fallback"] is True


def test_budget_blocks_before_synthetic_provider(settings: Settings) -> None:
    with TestClient(create_app(settings)) as client:
        preview = _preview_synthetic(client, max_input_tokens=1)
        body = {
            "packet_id": preview["packet"]["packet_id"],
            "provider": "fake",
            "consent": _consent(preview["analysis_offer"]),
        }
        response = client.post("/v1/inventory/analyses", json=body)

        assert response.status_code == 201, response.text
        payload = response.json()
        assert payload["analysis"]["status"] == "deterministic_only"
        assert payload["receipt"]["status"] == "budget_blocked"
        assert payload["receipt"]["provider_calls"] == 0
        assert payload["receipt"]["network_calls"] == 0
        assert payload["receipt"]["fallback"] is True
        assert client.app.state.inventory_service.fake_provider.calls == 0

        second_consent = _consent(preview["analysis_offer"])
        second_consent["consent_receipt_id"] = CONSENT_ID_2
        second_consent["client_action_id"] = ACTION_ID_2
        repeated_block = client.post(
            "/v1/inventory/analyses",
            json={
                "packet_id": preview["packet"]["packet_id"],
                "provider": "fake",
                "consent": second_consent,
            },
        )
        assert repeated_block.status_code == 201
        assert repeated_block.json()["receipt"]["status"] == "budget_blocked"
        assert repeated_block.json()["receipt"]["provider_calls"] == 0


def test_low_output_budget_blocks_before_synthetic_provider(
    settings: Settings,
) -> None:
    with TestClient(create_app(settings)) as client:
        preview = _preview_synthetic(client, max_output_tokens=160, top_k=1)
        response = client.post(
            "/v1/inventory/analyses",
            json={
                "packet_id": preview["packet"]["packet_id"],
                "provider": "fake",
                "consent": _consent(preview["analysis_offer"]),
            },
        )

        assert response.status_code == 201, response.text
        receipt = response.json()["receipt"]
        assert receipt["status"] == "budget_blocked"
        assert receipt["error_code"] == "OUTPUT_TOKEN_BUDGET_EXCEEDED"
        assert receipt["provider_calls"] == 0
        assert receipt["network_calls"] == 0
        assert client.app.state.inventory_service.fake_provider.calls == 0


def test_nonzero_synthetic_cost_budget_is_rejected_by_schema(
    settings: Settings,
) -> None:
    with TestClient(create_app(settings)) as client:
        preview = _preview_synthetic(client)
        consent = _consent(preview["analysis_offer"])
        consent["budget"]["max_estimated_cost"] = 0.01
        response = client.post(
            "/v1/inventory/analyses",
            json={
                "packet_id": preview["packet"]["packet_id"],
                "provider": "fake",
                "consent": consent,
            },
        )

        assert response.status_code == 422
        assert response.json()["code"] == "REQUEST_VALIDATION_FAILED"
        assert client.app.state.inventory_service.fake_provider.calls == 0


def test_formula_like_consent_identifiers_are_rejected_before_provider(
    settings: Settings,
) -> None:
    with TestClient(create_app(settings)) as client:
        preview = _preview_synthetic(client)
        consent = _consent(preview["analysis_offer"])
        formula_value = "=SAFE_FORMULA"
        secret_like_value = "sk-fixture-secret-must-not-echo"
        consent["consent_receipt_id"] = formula_value
        consent["client_action_id"] = "@SUM(A1:A2)"
        response = client.post(
            "/v1/inventory/analyses",
            json={
                "packet_id": preview["packet"]["packet_id"],
                "provider": "fake",
                "consent": consent,
                "api_key": secret_like_value,
            },
        )

        assert response.status_code == 422
        payload = response.json()
        assert payload["code"] == "REQUEST_VALIDATION_FAILED"
        assert formula_value not in response.text
        assert secret_like_value not in response.text
        assert payload["details"]["errors"]
        assert all(
            set(error) <= {"type", "loc", "msg"}
            for error in payload["details"]["errors"]
        )
        assert client.app.state.inventory_service.fake_provider.calls == 0


def test_local_full_cloud_mode_is_rejected(settings: Settings) -> None:
    with TestClient(create_app(settings)) as client:
        scan = client.post(
            "/v1/inventory/scans",
            json={
                "fixture_id": "standard",
                "profile": "inventory_metadata",
                "compute_hash": False,
            },
        ).json()
        response = client.post(
            "/v1/inventory/analysis-packets/preview",
            json={
                "snapshot_id": scan["snapshot_id"],
                "artifact_privacy_mode": "local_full",
                "analysis_execution_mode": "cloud_metadata_minimized",
            },
        )

    assert response.status_code == 409
    assert response.json()["code"] == "SYNTHETIC_PRIVACY_MODE_MISMATCH"


def test_receipt_id_cannot_be_reused_for_changed_binding(settings: Settings) -> None:
    with TestClient(create_app(settings)) as client:
        preview = _preview_synthetic(client)
        consent = _consent(preview["analysis_offer"])
        first = client.post(
            "/v1/inventory/analyses",
            json={
                "packet_id": preview["packet"]["packet_id"],
                "provider": "fake",
                "consent": consent,
            },
        )
        changed = deepcopy(consent)
        changed["client_action_id"] = ACTION_ID_3
        changed["packet_bytes"] = int(changed["packet_bytes"]) + 1
        reused = client.post(
            "/v1/inventory/analyses",
            json={
                "packet_id": preview["packet"]["packet_id"],
                "provider": "fake",
                "consent": changed,
            },
        )

        assert first.status_code == 201
        assert reused.status_code == 409
        assert reused.json()["code"] == "ANALYSIS_CONSENT_REUSED"
        assert client.app.state.inventory_service.fake_provider.calls == 1


def test_replay_cannot_change_outer_packet_id(settings: Settings) -> None:
    with TestClient(create_app(settings)) as client:
        original_preview = _preview_synthetic(client)
        original_consent = _consent(original_preview["analysis_offer"])
        first = client.post(
            "/v1/inventory/analyses",
            json={
                "packet_id": original_preview["packet"]["packet_id"],
                "provider": "fake",
                "consent": original_consent,
            },
        )
        changed_preview = _preview_synthetic(client, top_k=1)
        replay = client.post(
            "/v1/inventory/analyses",
            json={
                "packet_id": changed_preview["packet"]["packet_id"],
                "provider": "fake",
                "consent": original_consent,
            },
        )

        assert first.status_code == 201
        assert replay.status_code == 409
        assert replay.json()["code"] in {
            "ANALYSIS_CONSENT_MISMATCH",
            "ANALYSIS_CONSENT_REUSED",
        }
        assert client.app.state.inventory_service.fake_provider.calls == 1


def test_reserved_consent_after_interruption_is_not_replayed(
    settings: Settings,
) -> None:
    with TestClient(create_app(settings)) as client:
        preview = _preview_synthetic(client)
        consent = _consent(preview["analysis_offer"])
        client.app.state.repository.consume_analysis_consent(
            AnalysisConsentV1.model_validate(consent)
        )

        response = client.post(
            "/v1/inventory/analyses",
            json={
                "packet_id": preview["packet"]["packet_id"],
                "provider": "fake",
                "consent": consent,
            },
        )

        assert response.status_code == 409
        assert response.json()["code"] == "ANALYSIS_CONSENT_IN_PROGRESS"
        assert client.app.state.inventory_service.fake_provider.calls == 0


def test_synthetic_persistence_rolls_back_when_consent_finalize_fails(
    settings: Settings,
) -> None:
    with TestClient(create_app(settings)) as client:
        preview = _preview_synthetic(client)
        body = {
            "packet_id": preview["packet"]["packet_id"],
            "provider": "fake",
            "consent": _consent(preview["analysis_offer"]),
        }
        with sqlite3.connect(settings.database_path) as connection:
            connection.execute(
                """
                CREATE TRIGGER fail_synthetic_consent_finalize
                BEFORE UPDATE OF status ON analysis_consent_receipts
                WHEN NEW.status = 'consumed'
                BEGIN
                    SELECT RAISE(ABORT, 'CONTROLLED_CONSENT_FINALIZE_FAILURE');
                END
                """
            )

        with pytest.raises(
            sqlite3.IntegrityError,
            match="CONTROLLED_CONSENT_FINALIZE_FAILURE",
        ):
            client.post("/v1/inventory/analyses", json=body)

        assert client.app.state.inventory_service.fake_provider.calls == 1
        with sqlite3.connect(settings.database_path) as connection:
            consent_row = connection.execute(
                """
                SELECT status, receipt_json, analysis_id, model_receipt_id
                FROM analysis_consent_receipts
                WHERE consent_receipt_id = ?
                """,
                (CONSENT_ID_1,),
            ).fetchone()
            analysis_count = connection.execute(
                "SELECT COUNT(*) FROM ai_analyses"
            ).fetchone()[0]
            model_receipt_count = connection.execute(
                "SELECT COUNT(*) FROM model_call_receipts"
            ).fetchone()[0]

        assert consent_row == ("reserved", None, None, None)
        assert analysis_count == 0
        assert model_receipt_count == 0

        replay = client.post("/v1/inventory/analyses", json=body)
        assert replay.status_code == 409, replay.text
        assert replay.json()["code"] == "ANALYSIS_CONSENT_IN_PROGRESS"
        assert client.app.state.inventory_service.fake_provider.calls == 1
