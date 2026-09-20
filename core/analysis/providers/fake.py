from __future__ import annotations

import hashlib
from time import perf_counter, sleep

from core.analysis.gateway import ModelResult, ModelUsage
from core.analysis.schemas import AIFindingV1, AIAnalysisV1, AnalysisPacketV1
from core.inventory.models import canonical_json


class FakeSchemaError(ValueError):
    def __init__(self, usage: ModelUsage):
        super().__init__("FAKE_SCHEMA_FAILURE")
        self.usage = usage


class FakeProviderError(RuntimeError):
    def __init__(self, usage: ModelUsage):
        super().__init__("FAKE_PROVIDER_FAILURE")
        self.usage = usage


class FakeTimeoutError(TimeoutError):
    def __init__(self, latency_ms: int):
        super().__init__("FAKE_COOPERATIVE_TIMEOUT")
        self.latency_ms = latency_ms


def build_fake_analysis(
    packet: AnalysisPacketV1,
    *,
    dangling_reference: bool = False,
) -> AIAnalysisV1:
    selected = packet.top_objects[:3]
    findings: list[AIFindingV1] = []
    for index, item in enumerate(selected, start=1):
        object_id = (
            "obj_missing"
            if dangling_reference and index == 1
            else item.object_id
        )
        evidence_id = (
            "ev_missing"
            if dangling_reference and index == 1
            else item.evidence_ids[0]
        )
        findings.append(
            AIFindingV1(
                finding_id=f"finding_{index:03d}",
                object_ids=[object_id],
                evidence_ids=[evidence_id],
                observation="该对象值得结合来源、唯一性与重建成本人工核实。",
                recommendation=(
                    "archive_consider"
                    if item.object_type in {"archive", "installer"}
                    else "review"
                ),
            )
        )
    analysis_digest = hashlib.sha256(
        f"{packet.packet_sha256}\0fake\0{FakeProvider.model_name}".encode("utf-8")
    ).hexdigest()
    return AIAnalysisV1(
        schema_version="1.0",
        analysis_id=f"analysis_{analysis_digest[:24]}",
        packet_id=packet.packet_id,
        status="ai_complete",
        provider="fake",
        model=FakeProvider.model_name,
        summary="AI 帮你整理的观察仅用于辅助判断，不代表已授权处理。",
        findings=findings,
        questions=["这些对象是否仍在使用，且是否有可验证的备份或重建方式？"],
        limitations=[
            "仅分析结构化 fixture 元数据。",
            "未读取内容，未核验重复，也未执行任何文件动作。",
        ],
    )


class FakeProvider:
    provider_name = "fake"
    model_name = "fixture-analyst-v1"

    def __init__(
        self,
        *,
        fail: bool = False,
        dangling_reference: bool = False,
        schema_failures: int = 0,
        latency_ms: int = 1,
    ):
        self.fail = fail
        self.dangling_reference = dangling_reference
        self.schema_failures = schema_failures
        self.latency_ms = latency_ms
        self.calls = 0

    def analyze(
        self,
        packet: AnalysisPacketV1,
        *,
        timeout_ms: int | None = None,
    ) -> ModelResult:
        started = perf_counter()
        self.calls += 1
        if timeout_ms is not None and self.latency_ms >= timeout_ms:
            sleep(timeout_ms / 1000)
            elapsed_ms = max(1, int((perf_counter() - started) * 1000))
            raise FakeTimeoutError(elapsed_ms)
        sleep(self.latency_ms / 1000)
        elapsed_ms = self.latency_ms
        input_tokens = max(1, len(canonical_json(packet).encode("utf-8")) // 4)
        if self.schema_failures > 0:
            self.schema_failures -= 1
            invalid_output = {
                "controlled_schema_error": True,
                "packet_id": packet.packet_id,
            }
            raise FakeSchemaError(
                ModelUsage(
                    input_tokens=input_tokens,
                    cached_input_tokens=0,
                    output_tokens=max(
                        1,
                        len(canonical_json(invalid_output).encode("utf-8")) // 4,
                    ),
                    latency_ms=elapsed_ms,
                )
            )
        if self.fail:
            raise FakeProviderError(
                ModelUsage(
                    input_tokens=input_tokens,
                    cached_input_tokens=0,
                    output_tokens=0,
                    latency_ms=elapsed_ms,
                )
            )
        analysis = build_fake_analysis(
            packet,
            dangling_reference=self.dangling_reference,
        )
        output_tokens = max(1, len(canonical_json(analysis).encode("utf-8")) // 4)
        return ModelResult(
            analysis=analysis,
            usage=ModelUsage(
                input_tokens=input_tokens,
                cached_input_tokens=0,
                output_tokens=output_tokens,
                latency_ms=elapsed_ms,
            ),
        )
