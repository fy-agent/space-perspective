from __future__ import annotations

import hashlib
from pathlib import Path


PARTIAL_CHUNK_SIZE = 64 * 1024
READ_CHUNK_SIZE = 1024 * 1024
PARTIAL_HASH_POLICY = "sha256-head-tail-64k-v1"


def partial_sha256(path: Path, size_bytes: int) -> str:
    digest = hashlib.sha256()
    digest.update(str(size_bytes).encode("ascii"))
    with path.open("rb") as source:
        digest.update(source.read(PARTIAL_CHUNK_SIZE))
        if size_bytes > PARTIAL_CHUNK_SIZE:
            source.seek(max(0, size_bytes - PARTIAL_CHUNK_SIZE))
            digest.update(source.read(PARTIAL_CHUNK_SIZE))
    return digest.hexdigest()


def full_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(READ_CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()
