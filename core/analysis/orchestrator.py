from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from time import perf_counter

from core.analysis.gateway import ModelGateway
from core.analysis.grounding import GroundingError, validate_grounding
from core.analysis.privacy import lint_share_safe_packet
from core.analysis.schemas import AIAnalysisV1, AnalysisPacketV1, ModelCallReceiptV1
from core.analysis.schemas import (
    AnalysisBudgetV1,
    AnalysisConsentV1,
    default_analysis_budget,
)
from core.analysis.providers.fake import (
    FakeProviderError,
    FakeSchemaError,
    FakeTimeoutError,
    build_fake_analysis,
)
from core.audit.model_calls import make_receipt
from core.inventory.models import canonical_json


PROMPT_VERSION = "report-analysis-v1"
AI_SCHEMA_VERSION = "ai-analysis-v1"


@dataclass(slots=True)
class ProductAnalysisCache:
    values: dict[str, AIAnalysisV1] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AnalysisOutcome:
    analysis: AIAnalysisV1
    receipt: ModelCallReceiptV1


def _cache_key(packet: AnalysisPacketV1, provider: str, model: str) -> str:
    return hashlib.sha256(
        (
            f"{packet.packet_sha256}\0{PROMPT_VERSION}\0{AI_SCHEMA_VERSION}"
            f"\0{provider}\0{model}"
        ).encode("utf-8")
    ).hexdigest()


def _bind_analysis_to_consent(
    analysis: AIAnalysisV1,
    consent: AnalysisConsentV1 | None,
) -> AIAnalysisV1:
    if consent is None:
        return analysis
    consent_analysis_digest = hashlib.sha256(
        (
            f"{consent.packet_sha256}\0{analysis.provider}\0{analysis.model}"
            f"\0{consent.consent_receipt_id}\0{consent.client_action_id}"
        ).encode("utf-8")
    ).hexdigest()
    return analysis.model_copy(
        update={
            "analysis_id": f"analysis_{consent_analysis_digest[:24]}",
        }
    )


def _fallback(
    packet: AnalysisPacketV1,
    *,
    provider: str,
    model: str,
    status: str,
    provider_calls: int,
    error_code: str | None,
    cache_key: str,
    input_tokens: int = 0,
    cached_input_tokens: int = 0,
    output_tokens: int = 0,
    latency_ms: int = 0,
    analysis_status: str | None = None,
    consent: AnalysisConsentV1 | None = None,
    budget: AnalysisBudgetV1 | None = None,
    fallback: bool = True,
) -> AnalysisOutcome:
    digest = hashlib.sha256(
        (
            f"{packet.packet_sha256}\0{provider}\0fallback\0{status}"
            f"\0{error_code or ''}\0"
            f"{consent.consent_receipt_id if consent else ''}"
        ).encode("utf-8")
    ).hexdigest()
    analysis = AIAnalysisV1(
        schema_version="1.0",
        analysis_id=f"analysis_{digest[:24]}",
        packet_id=packet.packet_id,
        status=analysis_status
        or ("deterministic_only" if provider == "none" else "ai_failed_fallback"),
        provider=provider,
        model=model,
        summary="已生成确定性基础报告；AI 观察未合并。",
        findings=[],
        questions=[],
        limitations=["AI 不可用或未启用，报告数字与表格仍由确定性代码生成。"],
    )
    return AnalysisOutcome(
        analysis=analysis,
        receipt=make_receipt(
            packet_sha256=packet.packet_sha256,
            provider=provider,
            model=model,
            cache_key=cache_key,
            status=status,
            provider_calls=provider_calls,
            input_tokens=input_tokens,
            cached_input_tokens=cached_input_tokens,
            output_tokens=output_tokens,
            latency_ms=latency_ms,
            error_code=error_code,
            consent_receipt_id=(
                consent.consent_receipt_id if consent is not None else None
            ),
            client_action_id=consent.client_action_id if consent is not None else None,
            consent_status="consumed" if consent is not None else "not_required",
            budget=budget,
            cost_basis=consent.cost_basis if consent is not None else None,
            fallback=fallback,
        ),
    )


def estimate_output_tokens(_packet: AnalysisPacketV1) -> int:
    analysis = build_fake_analysis(_packet)
    return max(1, len(canonical_json(analysis).encode("utf-8")) // 4)


def analyze_packet(
    packet: AnalysisPacketV1,
    *,
    provider: str,
    gateway: ModelGateway | None = None,
    cache: ProductAnalysisCache | None = None,
    max_input_tokens: int = 12_000,
    budget: AnalysisBudgetV1 | None = None,
    consent: AnalysisConsentV1 | None = None,
) -> AnalysisOutcome:
    if provider == "none":
        key = _cache_key(packet, "none", "deterministic")
        return _fallback(
            packet,
            provider="none",
            model="deterministic",
            status="not_called",
            provider_calls=0,
            error_code=None,
            cache_key=key,
            fallback=False,
        )
    if provider != "fake" or gateway is None:
        raise ValueError("当前冻结边界只允许 provider none|fake")
    key = _cache_key(packet, "fake", gateway.model_name)
    if budget is None:
        default_budget = default_analysis_budget()
        effective_budget = AnalysisBudgetV1.model_validate(
            {
                **default_budget.model_dump(),
                "max_input_tokens": max_input_tokens,
            }
        )
    else:
        effective_budget = budget
    lint = lint_share_safe_packet(packet)
    if not lint.passed:
        return _fallback(
            packet,
            provider="fake",
            model=gateway.model_name,
            status="privacy_blocked",
            provider_calls=0,
            error_code="PRIVACY_LINT_FAILED",
            cache_key=key,
            analysis_status=(
                "deterministic_only"
                if packet.analysis_execution_mode == "cloud_metadata_minimized"
                else None
            ),
            consent=consent,
            budget=effective_budget,
        )
    estimated_input_tokens = max(
        1,
        len(canonical_json(packet).encode("utf-8")) // 4,
    )
    packet_bytes = len(canonical_json(packet).encode("utf-8"))
    estimated_output_tokens = estimate_output_tokens(packet)
    budget_error = None
    if packet_bytes > effective_budget.max_packet_bytes:
        budget_error = "PACKET_BYTE_BUDGET_EXCEEDED"
    elif estimated_input_tokens > effective_budget.max_input_tokens:
        budget_error = "INPUT_TOKEN_BUDGET_EXCEEDED"
    elif estimated_output_tokens > effective_budget.max_output_tokens:
        budget_error = "OUTPUT_TOKEN_BUDGET_EXCEEDED"
    if budget_error is not None:
        return _fallback(
            packet,
            provider="fake",
            model=gateway.model_name,
            status="budget_blocked",
            provider_calls=0,
            error_code=budget_error,
            cache_key=key,
            input_tokens=estimated_input_tokens,
            analysis_status=(
                "deterministic_only"
                if packet.analysis_execution_mode == "cloud_metadata_minimized"
                else None
            ),
            consent=consent,
            budget=effective_budget,
        )
    product_cache = cache or ProductAnalysisCache()
    cached = product_cache.values.get(key)
    if cached is not None:
        cached_analysis = _bind_analysis_to_consent(cached, consent)
        return AnalysisOutcome(
            analysis=cached_analysis,
            receipt=make_receipt(
                packet_sha256=packet.packet_sha256,
                provider="fake",
                model=gateway.model_name,
                cache_key=key,
                status="cache_hit",
                provider_calls=0,
                cached_input_tokens=0,
                consent_receipt_id=(
                    consent.consent_receipt_id if consent is not None else None
                ),
                client_action_id=(
                    consent.client_action_id if consent is not None else None
                ),
                consent_status="consumed" if consent is not None else "not_required",
                budget=effective_budget if consent is not None else None,
                cost_basis=consent.cost_basis if consent is not None else None,
            ),
        )
    before = gateway.calls
    provider_started = perf_counter()
    result = None
    total_input_tokens = 0
    total_cached_input_tokens = 0
    total_output_tokens = 0
    total_latency_ms = 0
    provider_deadline = (
        provider_started + (effective_budget.timeout_ms / 1000)
    )

    def timeout_outcome() -> AnalysisOutcome:
        return _fallback(
            packet,
            provider="fake",
            model=gateway.model_name,
            status="provider_failed",
            provider_calls=gateway.calls - before,
            error_code="SYNTHETIC_TIMEOUT",
            cache_key=key,
            input_tokens=total_input_tokens,
            cached_input_tokens=total_cached_input_tokens,
            output_tokens=total_output_tokens,
            latency_ms=max(
                total_latency_ms,
                int((perf_counter() - provider_started) * 1000),
            ),
            consent=consent,
            budget=effective_budget,
        )

    def deadline_reached() -> bool:
        return perf_counter() >= provider_deadline

    for attempt in range(effective_budget.max_schema_retries + 1):
        remaining_timeout_ms = int(
            max(0.0, provider_deadline - perf_counter()) * 1000
        )
        if remaining_timeout_ms <= 0:
            return timeout_outcome()
        try:
            result = gateway.analyze(
                packet,
                timeout_ms=remaining_timeout_ms,
            )
            total_input_tokens += result.usage.input_tokens
            total_cached_input_tokens += result.usage.cached_input_tokens
            total_output_tokens += result.usage.output_tokens
            total_latency_ms += result.usage.latency_ms
            if deadline_reached():
                return timeout_outcome()
            break
        except FakeTimeoutError as exc:
            total_latency_ms += exc.latency_ms
            return timeout_outcome()
        except FakeProviderError as exc:
            total_input_tokens += exc.usage.input_tokens
            total_cached_input_tokens += exc.usage.cached_input_tokens
            total_output_tokens += exc.usage.output_tokens
            total_latency_ms += exc.usage.latency_ms
            if deadline_reached():
                return timeout_outcome()
            return _fallback(
                packet,
                provider="fake",
                model=gateway.model_name,
                status="provider_failed",
                provider_calls=gateway.calls - before,
                error_code="FAKE_PROVIDER_FAILED",
                cache_key=key,
                input_tokens=total_input_tokens,
                cached_input_tokens=total_cached_input_tokens,
                output_tokens=total_output_tokens,
                latency_ms=total_latency_ms,
                consent=consent,
                budget=effective_budget,
            )
        except FakeSchemaError as exc:
            total_input_tokens += exc.usage.input_tokens
            total_cached_input_tokens += exc.usage.cached_input_tokens
            total_output_tokens += exc.usage.output_tokens
            total_latency_ms += exc.usage.latency_ms
            if deadline_reached():
                return timeout_outcome()
            if (
                total_input_tokens > effective_budget.max_input_tokens
                or total_output_tokens > effective_budget.max_output_tokens
            ):
                return _fallback(
                    packet,
                    provider="fake",
                    model=gateway.model_name,
                    status="budget_blocked",
                    provider_calls=gateway.calls - before,
                    error_code="ACTUAL_TOKEN_BUDGET_EXCEEDED",
                    cache_key=key,
                    input_tokens=total_input_tokens,
                    cached_input_tokens=total_cached_input_tokens,
                    output_tokens=total_output_tokens,
                    latency_ms=total_latency_ms,
                    analysis_status=(
                        "deterministic_only"
                        if packet.analysis_execution_mode
                        == "cloud_metadata_minimized"
                        else None
                    ),
                    consent=consent,
                    budget=effective_budget,
                )
            if attempt >= effective_budget.max_schema_retries:
                return _fallback(
                    packet,
                    provider="fake",
                    model=gateway.model_name,
                    status="schema_failed",
                    provider_calls=gateway.calls - before,
                    error_code="AI_SCHEMA_INVALID",
                    cache_key=key,
                    input_tokens=total_input_tokens,
                    cached_input_tokens=total_cached_input_tokens,
                    output_tokens=total_output_tokens,
                    latency_ms=total_latency_ms,
                    consent=consent,
                    budget=effective_budget,
                )
            if (
                total_input_tokens + estimated_input_tokens
                > effective_budget.max_input_tokens
                or total_output_tokens + estimated_output_tokens
                > effective_budget.max_output_tokens
            ):
                return _fallback(
                    packet,
                    provider="fake",
                    model=gateway.model_name,
                    status="budget_blocked",
                    provider_calls=gateway.calls - before,
                    error_code="ACTUAL_TOKEN_BUDGET_EXCEEDED",
                    cache_key=key,
                    input_tokens=total_input_tokens,
                    cached_input_tokens=total_cached_input_tokens,
                    output_tokens=total_output_tokens,
                    latency_ms=total_latency_ms,
                    analysis_status=(
                        "deterministic_only"
                        if packet.analysis_execution_mode
                        == "cloud_metadata_minimized"
                        else None
                    ),
                    consent=consent,
                    budget=effective_budget,
                )
        except Exception:
            if deadline_reached():
                return timeout_outcome()
            return _fallback(
                packet,
                provider="fake",
                model=gateway.model_name,
                status="provider_failed",
                provider_calls=gateway.calls - before,
                error_code="FAKE_PROVIDER_FAILED",
                cache_key=key,
                input_tokens=total_input_tokens,
                cached_input_tokens=total_cached_input_tokens,
                output_tokens=total_output_tokens,
                latency_ms=max(
                    total_latency_ms,
                    int((perf_counter() - provider_started) * 1000),
                ),
                consent=consent,
                budget=effective_budget,
            )
    if result is None:
        raise AssertionError("synthetic provider loop produced no result")
    if (
        total_input_tokens > effective_budget.max_input_tokens
        or total_output_tokens > effective_budget.max_output_tokens
    ):
        return _fallback(
            packet,
            provider="fake",
            model=gateway.model_name,
            status="budget_blocked",
            provider_calls=gateway.calls - before,
            error_code="ACTUAL_TOKEN_BUDGET_EXCEEDED",
            cache_key=key,
            input_tokens=total_input_tokens,
            cached_input_tokens=total_cached_input_tokens,
            output_tokens=total_output_tokens,
            latency_ms=total_latency_ms,
            analysis_status=(
                "deterministic_only"
                if packet.analysis_execution_mode == "cloud_metadata_minimized"
                else None
            ),
            consent=consent,
            budget=effective_budget,
        )
    try:
        validate_grounding(packet, result.analysis)
    except GroundingError:
        return _fallback(
            packet,
            provider="fake",
            model=gateway.model_name,
            status="grounding_failed",
            provider_calls=gateway.calls - before,
            error_code="GROUNDING_FAILED",
            cache_key=key,
            input_tokens=total_input_tokens,
            cached_input_tokens=total_cached_input_tokens,
            output_tokens=total_output_tokens,
            latency_ms=total_latency_ms,
            consent=consent,
            budget=effective_budget,
        )
    product_cache.values[key] = result.analysis
    consent_analysis = _bind_analysis_to_consent(result.analysis, consent)
    return AnalysisOutcome(
        analysis=consent_analysis,
        receipt=make_receipt(
            packet_sha256=packet.packet_sha256,
            provider="fake",
            model=gateway.model_name,
            cache_key=key,
            status="succeeded",
            provider_calls=gateway.calls - before,
            input_tokens=total_input_tokens,
            cached_input_tokens=total_cached_input_tokens,
            output_tokens=total_output_tokens,
            latency_ms=total_latency_ms,
            consent_receipt_id=(
                consent.consent_receipt_id if consent is not None else None
            ),
            client_action_id=consent.client_action_id if consent is not None else None,
            consent_status="consumed" if consent is not None else "not_required",
            budget=effective_budget if consent is not None else None,
            cost_basis=consent.cost_basis if consent is not None else None,
        ),
    )
