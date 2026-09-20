from __future__ import annotations

import hashlib
from pathlib import Path
import sys
import tempfile
import time
from typing import Callable

from fastapi.testclient import TestClient

ROOT = Path(__file__).parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.app.config import Settings
from core.app.main import create_app
from fixtures.generate import generate


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def wait_for_scan(client: TestClient, scan_id: str) -> dict:
    for _ in range(400):
        response = client.get(f"/scan/{scan_id}")
        response.raise_for_status()
        session = response.json()
        if session["status"] in {"completed", "partial", "cancelled", "failed"}:
            return session
        time.sleep(0.01)
    raise RuntimeError("scan timeout")


def run_scenario(
    sandbox: Path,
    *,
    prepare_corpus: Callable[[Path], None] | None = None,
) -> dict[str, object]:
    corpus = sandbox / "demo-corpus"
    generate(corpus)
    if prepare_corpus is not None:
        prepare_corpus(corpus)
    corpus = corpus.resolve()
    original_files = [path.resolve() for path in corpus.rglob("*") if path.is_file()]
    before = {
        str(path): {"hash": digest(path), "mtime_ns": path.stat().st_mtime_ns}
        for path in original_files
    }
    settings = Settings(
        database_path=sandbox / "app-data" / "smoke.sqlite3",
        quarantine_path=sandbox / "quarantine",
        allowed_origins=("http://127.0.0.1:5173",),
    )

    with TestClient(create_app(settings)) as client:
        health = client.get("/health").json()
        assert health["status"] == "ok"
        assert health["capabilities"]["real_upload_enabled"] is False

        created = client.post("/scan", json={"paths": [str(corpus)]})
        assert created.status_code == 202, created.text
        scan_id = created.json()["id"]
        session = wait_for_scan(client, scan_id)
        assert session["status"] == "completed", session

        for path in original_files:
            assert path.exists()
            assert digest(path) == before[str(path)]["hash"]
            assert path.stat().st_mtime_ns == before[str(path)]["mtime_ns"]

        overview = client.get("/fileintel/overview", params={"scan_session_id": scan_id}).json()
        assert overview["total_files"] == len(original_files)
        groups = client.get("/dups", params={"scan_session_id": scan_id}).json()["items"]
        assert groups and groups[0]["kind"] == "exact"
        suggestions = client.get(
            "/suggestions", params={"scan_session_id": scan_id, "page_size": 500}
        ).json()["items"]
        assert all(not item["default_selected"] for item in suggestions if item["risk_level"] == "high")
        low_risk = next(item for item in suggestions if item["default_selected"])

        preview_before = {
            str(path): (path.exists(), digest(path), path.stat().st_mtime_ns)
            for path in original_files
        }
        preview = client.post("/operations/preview", json={
            "action_type": "quarantine",
            "suggestion_ids": [low_risk["id"]],
            "target_policy": "app_quarantine",
        })
        assert preview.status_code == 200, preview.text
        plan = preview.json()
        for path in original_files:
            assert (path.exists(), digest(path), path.stat().st_mtime_ns) == preview_before[str(path)]

        executed = client.post("/operations/execute", json={
            "operation_plan_id": plan["id"],
            "confirm": True,
            "client_seen_plan_version": plan["version"],
            "idempotency_key": "p0-smoke",
        })
        assert executed.status_code == 200, executed.text
        receipt = executed.json()
        assert receipt["status"] == "succeeded"
        candidate = Path(plan["items"][0]["display_path"])
        assert not candidate.exists()
        assert client.get(f"/operations/{receipt['id']}").status_code == 200
        quarantine = client.get(
            "/quarantine", params={"operation_id": receipt["id"]}
        ).json()["items"]
        assert len(quarantine) == 1
        quarantined = Path(quarantine[0]["quarantine_path"])
        assert quarantined.exists()
        same_volume = candidate.parent.stat().st_dev == quarantined.stat().st_dev

        undone = client.post(
            f"/operations/{receipt['id']}/undo",
            json={"confirm": True, "conflict_policy": "fail_on_conflict"},
        )
        assert undone.status_code == 200, undone.text
        assert undone.json()["status"] == "undone"
        assert candidate.exists()
        restored_hash = digest(candidate)
        assert restored_hash == before[str(candidate)]["hash"]

    return {
        "scan_status": session["status"],
        "files_indexed": session["files_indexed"],
        "operation_status": receipt["status"],
        "undo_status": undone.json()["status"],
        "restored_sha256": restored_hash,
        "same_volume": same_volume,
    }


def run() -> None:
    with tempfile.TemporaryDirectory(prefix="data-butler-smoke-") as temporary:
        result = run_scenario(Path(temporary))
    print("P0 smoke OK: scan -> overview -> dups -> suggestions -> preview -> quarantine -> receipt -> undo")
    print(f"Evidence: {result}")


if __name__ == "__main__":
    run()
