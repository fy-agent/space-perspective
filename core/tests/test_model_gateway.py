from __future__ import annotations

from core.analysis.orchestrator import ProductAnalysisCache, analyze_packet
from core.analysis.packet import build_packet
from core.analysis.providers.fake import FakeProvider
from core.tests._inventory_helpers import make_snapshot


def _packet(tmp_path):
    snapshot, _ = make_snapshot(tmp_path)
    return build_packet(
        snapshot,
        artifact_privacy_mode="share_safe",
        analysis_execution_mode="local_only",
    )


def test_none_provider_is_not_called(tmp_path) -> None:
    outcome = analyze_packet(_packet(tmp_path), provider="none")

    assert outcome.analysis.status == "deterministic_only"
    assert outcome.receipt.fallback is False
    assert outcome.receipt.provider_calls == 0
    assert outcome.receipt.network_calls == 0


def test_fake_provider_is_grounded_and_product_cache_reuses_result(tmp_path) -> None:
    packet = _packet(tmp_path)
    gateway = FakeProvider()
    cache = ProductAnalysisCache()

    first = analyze_packet(packet, provider="fake", gateway=gateway, cache=cache)
    second = analyze_packet(packet, provider="fake", gateway=gateway, cache=cache)

    assert first.analysis.status == "ai_complete"
    assert first.receipt.provider_calls == 1
    assert second.receipt.status == "cache_hit"
    assert second.receipt.provider_calls == 0
    assert gateway.calls == 1
    object_ids = {item.object_id for item in packet.top_objects}
    evidence_ids = {value for item in packet.top_objects for value in item.evidence_ids}
    assert all(set(item.object_ids) <= object_ids for item in first.analysis.findings)
    assert all(set(item.evidence_ids) <= evidence_ids for item in first.analysis.findings)


def test_dangling_ai_reference_falls_back(tmp_path) -> None:
    outcome = analyze_packet(
        _packet(tmp_path),
        provider="fake",
        gateway=FakeProvider(dangling_reference=True),
    )

    assert outcome.analysis.status == "ai_failed_fallback"
    assert outcome.analysis.findings == []
    assert outcome.receipt.status == "grounding_failed"
    assert outcome.receipt.network_calls == 0
    assert outcome.receipt.input_tokens > 0
    assert outcome.receipt.output_tokens > 0
    assert outcome.receipt.latency_ms > 0
