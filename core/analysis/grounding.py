from __future__ import annotations

import re

from core.analysis.schemas import AIAnalysisV1, AnalysisPacketV1


class GroundingError(ValueError):
    pass


NUMERIC_CLAIM = re.compile(r"\d")


def validate_grounding(
    packet: AnalysisPacketV1,
    analysis: AIAnalysisV1,
) -> None:
    object_ids = {item.object_id for item in packet.top_objects}
    evidence_ids = {
        evidence_id
        for item in packet.top_objects
        for evidence_id in item.evidence_ids
    }
    if analysis.packet_id != packet.packet_id:
        raise GroundingError("analysis packet_id 不一致")
    for finding in analysis.findings:
        missing_objects = set(finding.object_ids) - object_ids
        missing_evidence = set(finding.evidence_ids) - evidence_ids
        if missing_objects or missing_evidence:
            raise GroundingError("AIAnalysisV1 含悬空 object/evidence 引用")
        if NUMERIC_CLAIM.search(finding.observation):
            raise GroundingError("模型观察不得生成权威空间数字")
