from __future__ import annotations

import re


CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def normalized_label(value: str, *, limit: int = 120) -> str:
    cleaned = CONTROL_CHARACTERS.sub("�", value).strip()
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: limit - 1] + "…"


def pseudonym(object_type: str, index: int) -> str:
    return f"{object_type}-{index:03d}"
