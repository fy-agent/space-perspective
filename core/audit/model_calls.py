from __future__ import annotations

import hashlib

from core.analysis.schemas import AnalysisBudgetV1, ModelCallReceiptV1


def make_receipt(
    *,
    packet_sha256: str,
    provider: str,
    model: str,
    cache_key: str,
    status: str,
    provider_calls: int,
    input_tokens: int = 0,
    cached_input_tokens: int = 0,
    output_tokens: int = 0,
    latency_ms: int = 0,
    error_code: str | None = None,
    consent_receipt_id: str | None = None,
    client_action_id: str | None = None,
    consent_status: str = "not_required",
    budget: AnalysisBudgetV1 | None = None,
    cost_basis: str | None = None,
    fallback: bool = False,
) -> ModelCallReceiptV1:
    receipt_digest = hashlib.sha256(
        (
            f"{cache_key}\0{status}\0{provider_calls}\0{error_code or ''}"
            f"\0{consent_receipt_id or ''}\0{client_action_id or ''}"
        ).encode("utf-8")
    ).hexdigest()
    return ModelCallReceiptV1(
        receipt_id=f"model_receipt_{receipt_digest[:24]}",
        packet_sha256=packet_sha256,
        provider=provider,
        model=model,
        prompt_version="report-analysis-v1",
        schema_version="ai-analysis-v1",
        cache_key=cache_key,
        status=status,
        provider_calls=provider_calls,
        network_calls=0,
        synthetic=consent_receipt_id is not None,
        input_tokens=input_tokens,
        cached_input_tokens=cached_input_tokens,
        output_tokens=output_tokens,
        estimated_cost=0,
        latency_ms=latency_ms,
        error_code=error_code,
        consent_receipt_id=consent_receipt_id,
        client_action_id=client_action_id,
        consent_status=consent_status,
        budget=budget,
        cost_basis=cost_basis,
        fallback=fallback,
    )
