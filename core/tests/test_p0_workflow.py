from __future__ import annotations

import hashlib
from pathlib import Path
import time

from fastapi.testclient import TestClient

from core.app.config import Settings
from core.app.main import create_app


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _wait_for_scan(client: TestClient, scan_id: str) -> dict:
    for _ in range(200):
        payload = client.get(f"/scan/{scan_id}").json()
        if payload["status"] in {"completed", "partial", "cancelled", "failed"}:
            return payload
        time.sleep(0.01)
    raise AssertionError("scan did not finish")


def _make_corpus(root: Path) -> dict[str, Path]:
    downloads = root / "Downloads"
    documents = root / "Documents"
    desktop = root / "Desktop"
    downloads.mkdir(parents=True)
    documents.mkdir()
    desktop.mkdir()
    duplicate_a = downloads / "repeat-a.txt"
    duplicate_b = downloads / "repeat-b.txt"
    duplicate_a.write_text("same local content", encoding="utf-8")
    duplicate_b.write_text("same local content", encoding="utf-8")
    protected = documents / "合同-样本.txt"
    protected.write_text("placeholder only", encoding="utf-8")
    unique = desktop / "notes.md"
    unique.write_text("unique", encoding="utf-8")
    return {"a": duplicate_a, "b": duplicate_b, "protected": protected, "unique": unique}


def _client(tmp_path: Path) -> TestClient:
    return TestClient(create_app(Settings(
        database_path=tmp_path / "app-data" / "test.sqlite3",
        quarantine_path=tmp_path / "quarantine",
        allowed_origins=("http://127.0.0.1:5173",),
    )))


def test_complete_p0_loop_is_read_only_until_execute_and_undo_restores(tmp_path: Path) -> None:
    corpus_root = tmp_path / "corpus"
    paths = _make_corpus(corpus_root)
    before = {
        name: (str(path), _sha256(path), path.stat().st_mtime_ns)
        for name, path in paths.items()
    }

    with _client(tmp_path) as client:
        created = client.post("/scan", json={"paths": [str(corpus_root)]})
        assert created.status_code == 202
        scan_id = created.json()["id"]
        session = _wait_for_scan(client, scan_id)
        assert session["status"] == "completed", session.get("error_summary")
        assert session["files_indexed"] == 4

        for name, path in paths.items():
            assert (str(path), _sha256(path), path.stat().st_mtime_ns) == before[name]

        stream = client.get(f"/scan/{scan_id}/stream")
        assert stream.status_code == 200
        assert stream.headers["content-type"].startswith("text/event-stream")
        assert "event: scan_event" in stream.text
        assert '"type":"completed"' in stream.text

        overview = client.get("/fileintel/overview", params={"scan_session_id": scan_id}).json()
        assert overview["total_files"] == 4
        assert overview["total_size_bytes"] == sum(path.stat().st_size for path in paths.values())

        groups = client.get("/dups", params={"scan_session_id": scan_id}).json()["items"]
        assert len(groups) == 1
        assert groups[0]["member_count"] == 2
        assert client.get(
            "/dups", params={"scan_session_id": scan_id, "min_reclaimable_bytes": 29}
        ).json()["items"] == []
        suggestions = client.get(
            "/suggestions", params={"scan_session_id": scan_id, "default_selected": "true"}
        ).json()["items"]
        assert len(suggestions) == 1
        candidate_path = next(
            Path(item["display_path"])
            for item in [{"display_path": asset["abs_path"]} for asset in client.get(
                "/assets", params={"scan_session_id": scan_id}
            ).json()["items"]]
            if item["display_path"].endswith(("repeat-a.txt", "repeat-b.txt"))
            and item["display_path"] != next(
                asset["abs_path"] for asset in client.get(
                    f"/assets/{groups[0]['keep_asset_id']}"
                ).json().values() if isinstance(asset, dict)
            )
        )

        preview = client.post("/operations/preview", json={
            "action_type": "quarantine",
            "suggestion_ids": [suggestions[0]["id"]],
            "target_policy": "app_quarantine",
        })
        assert preview.status_code == 200, preview.text
        plan = preview.json()
        assert candidate_path.exists()
        assert _sha256(candidate_path) == before["a"][1]

        receipt_response = client.post("/operations/execute", json={
            "operation_plan_id": plan["id"],
            "confirm": True,
            "client_seen_plan_version": plan["version"],
            "idempotency_key": "workflow-success",
        })
        assert receipt_response.status_code == 200, receipt_response.text
        receipt = receipt_response.json()
        assert receipt["status"] == "succeeded"
        assert not candidate_path.exists()
        assert client.get(
            "/suggestions", params={"scan_session_id": scan_id, "default_selected": "true"}
        ).json()["items"] == []
        assert client.get("/dups", params={"scan_session_id": scan_id}).json()["items"] == []
        quarantine = client.get("/quarantine", params={"operation_id": receipt["id"]}).json()["items"]
        assert len(quarantine) == 1
        assert Path(quarantine[0]["quarantine_path"]).exists()

        undone = client.post(
            f"/operations/{receipt['id']}/undo", json={"confirm": True, "conflict_policy": "fail_on_conflict"}
        )
        assert undone.status_code == 200, undone.text
        assert undone.json()["status"] == "undone"
        assert candidate_path.exists()
        assert _sha256(candidate_path) == before["a"][1]
        assert len(client.get(
            "/suggestions", params={"scan_session_id": scan_id, "default_selected": "true"}
        ).json()["items"]) == 1
        assert len(client.get("/dups", params={"scan_session_id": scan_id}).json()["items"]) == 1


def test_high_risk_snapshot_change_and_restore_conflict_are_blocked(tmp_path: Path) -> None:
    root = tmp_path / "corpus"
    paths = _make_corpus(root)
    with _client(tmp_path) as client:
        scan_id = client.post("/scan", json={"paths": [str(root)]}).json()["id"]
        _wait_for_scan(client, scan_id)
        assets = client.get("/assets", params={"scan_session_id": scan_id}).json()["items"]
        protected = next(item for item in assets if item["abs_path"] == str(paths["protected"]))
        denied = client.post("/operations/preview", json={
            "action_type": "quarantine", "asset_ids": [protected["id"]],
            "target_policy": "app_quarantine",
        })
        assert denied.status_code == 409
        assert denied.json()["code"] == "HIGH_RISK_PROTECTED"

        suggestion = client.get(
            "/suggestions", params={"scan_session_id": scan_id, "default_selected": "true"}
        ).json()["items"][0]
        plan = client.post("/operations/preview", json={
            "action_type": "quarantine", "suggestion_ids": [suggestion["id"]],
            "target_policy": "app_quarantine",
        }).json()
        candidate = Path(plan["items"][0]["display_path"])
        candidate.write_text("changed after preview", encoding="utf-8")
        failed = client.post("/operations/execute", json={
            "operation_plan_id": plan["id"], "confirm": True,
            "client_seen_plan_version": plan["version"],
        }).json()
        assert failed["status"] == "failed"
        assert failed["file_results"][0]["error"]["code"] == "ASSET_SNAPSHOT_CHANGED"
        assert candidate.exists()

        # Re-scan to create a fresh snapshot, then prove undo never overwrites a conflict.
        candidate.write_text("same local content", encoding="utf-8")
        scan_id = client.post("/scan", json={"paths": [str(root)]}).json()["id"]
        _wait_for_scan(client, scan_id)
        suggestion = client.get(
            "/suggestions", params={"scan_session_id": scan_id, "default_selected": "true"}
        ).json()["items"][0]
        plan = client.post("/operations/preview", json={
            "action_type": "quarantine", "suggestion_ids": [suggestion["id"]],
            "target_policy": "app_quarantine",
        }).json()
        candidate = Path(plan["items"][0]["display_path"])
        receipt = client.post("/operations/execute", json={
            "operation_plan_id": plan["id"], "confirm": True,
            "client_seen_plan_version": plan["version"],
        }).json()
        assert receipt["status"] == "succeeded"
        candidate.write_text("do not overwrite", encoding="utf-8")
        conflict = client.post(
            f"/operations/{receipt['id']}/undo", json={"confirm": True}
        ).json()
        assert conflict["status"] == "undo_partial"
        assert conflict["file_results"][0]["error"]["code"] == "RESTORE_CONFLICT"
        assert candidate.read_text(encoding="utf-8") == "do not overwrite"


def test_scan_rejects_relative_and_symlink_roots(tmp_path: Path) -> None:
    root = tmp_path / "corpus"
    root.mkdir()
    link = tmp_path / "linked"
    link.symlink_to(root, target_is_directory=True)
    with _client(tmp_path) as client:
        relative = client.post("/scan", json={"paths": ["relative"]})
        linked = client.post("/scan", json={"paths": [str(link)]})
        follow = client.post("/scan", json={
            "paths": [str(root)], "options": {"follow_symlinks": True}
        })
    assert relative.status_code == 422
    assert linked.status_code == 422
    assert follow.status_code == 422
