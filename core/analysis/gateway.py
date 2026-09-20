from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from core.analysis.schemas import AIAnalysisV1, AnalysisPacketV1


@dataclass(frozen=True, slots=True)
class ModelUsage:
    input_tokens: int
    cached_input_tokens: int
    output_tokens: int
    latency_ms: int


@dataclass(frozen=True, slots=True)
class ModelResult:
    analysis: AIAnalysisV1
    usage: ModelUsage


class ModelGateway(Protocol):
    provider_name: str
    model_name: str
    calls: int

    def analyze(
        self,
        packet: AnalysisPacketV1,
        *,
        timeout_ms: int | None = None,
    ) -> ModelResult: ...
