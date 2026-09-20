from __future__ import annotations

import pytest

import core.analysis.orchestrator as orchestrator_module
from core.analysis.orchestrator import analyze_packet
from core.analysis.packet import build_packet
from core.analysis.providers.fake import FakeProvider
from core.analysis.schemas import AnalysisBudgetV1, default_analysis_budget
from core.tests._inventory_helpers import make_snapshot


def test_provider_failure_does_not_block_base_report(tmp_path) -> None:
    snapshot, _ = make_snapshot(tmp_path)
    packet = build_packet(
        snapshot,
        artifact_privacy_mode="share_safe",
        analysis_execution_mode="local_only",
    )

    outcome = analyze_packet(
        packet,
        provider="fake",
        gateway=FakeProvider(fail=True),
    )

    assert outcome.analysis.status == "ai_failed_fallback"
    assert outcome.receipt.status == "provider_failed"
    assert outcome.receipt.provider_calls == 1
    assert outcome.receipt.network_calls == 0


def test_input_budget_blocks_provider_call(tmp_path) -> None:
    snapshot, _ = make_snapshot(tmp_path)
    packet = build_packet(
        snapshot,
        artifact_privacy_mode="share_safe",
        analysis_execution_mode="local_only",
    )
    gateway = FakeProvider()

    outcome = analyze_packet(
        packet,
        provider="fake",
        gateway=gateway,
        max_input_tokens=1,
    )

    assert outcome.analysis.status == "ai_failed_fallback"
    assert outcome.receipt.status == "budget_blocked"
    assert outcome.receipt.provider_calls == 0
    assert gateway.calls == 0


@pytest.mark.parametrize(
    ("failure_mode", "has_output_usage"),
    (("schema", True), ("provider", False)),
)
def test_aggregate_deadline_precedes_final_controlled_failure(
    tmp_path,
    monkeypatch,
    failure_mode: str,
    has_output_usage: bool,
) -> None:
    snapshot, _ = make_snapshot(tmp_path)
    packet = build_packet(
        snapshot,
        artifact_privacy_mode="share_safe",
        analysis_execution_mode="local_only",
    )
    gateway = FakeProvider(
        fail=failure_mode == "provider",
        schema_failures=1 if failure_mode == "schema" else 0,
    )
    clock_values = iter((0.0, 0.0, 0.101, 0.101))
    monkeypatch.setattr(
        orchestrator_module,
        "perf_counter",
        lambda: next(clock_values),
    )

    outcome = analyze_packet(
        packet,
        provider="fake",
        gateway=gateway,
        budget=AnalysisBudgetV1.model_validate(
            {
                **default_analysis_budget().model_dump(),
                "timeout_ms": 100,
                "max_schema_retries": 0,
            }
        ),
    )

    assert outcome.receipt.status == "provider_failed"
    assert outcome.receipt.error_code == "SYNTHETIC_TIMEOUT"
    assert outcome.receipt.provider_calls == 1
    assert outcome.receipt.input_tokens > 0
    assert (outcome.receipt.output_tokens > 0) is has_output_usage
    assert outcome.receipt.latency_ms == 101
