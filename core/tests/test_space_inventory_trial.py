from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock
import socket

import scripts.space_inventory_trial as trial


def test_cli_none_and_fake_fixture_e2e(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(trial, "TRIALS_ROOT", tmp_path / "trials")
    network = Mock(side_effect=AssertionError("network call is forbidden"))
    monkeypatch.setattr(socket, "create_connection", network)

    none_code, none_output = trial.run_trial(provider="none", privacy="local_full")
    fake_code, fake_output = trial.run_trial(provider="fake", privacy="share_safe")

    assert none_code == fake_code == 0
    for output in (none_output, fake_output):
        assert all((output / name).exists() for name in trial.EXPECTED_OUTPUTS)
        receipt = json.loads((output / "trial-receipt.json").read_text(encoding="utf-8"))
        assert receipt["product_content_reads"] == 0
        assert receipt["product_file_hashes"] == 0
        assert receipt["network_calls"] == 0
        assert receipt["fixture_integrity_hashes"] >= 1
        assert receipt["fixture_unchanged"] is True
        assert trial.verify_trial(output)["status"] == "passed"
    none_receipt = json.loads(
        (none_output / "trial-receipt.json").read_text(encoding="utf-8")
    )
    fake_receipt = json.loads(
        (fake_output / "trial-receipt.json").read_text(encoding="utf-8")
    )
    assert none_receipt["provider_calls"] == 0
    assert fake_receipt["provider_calls"] == 1
    assert network.call_count == 0
    fake_analysis = (fake_output / "analysis.json").read_text(encoding="utf-8")
    assert "delete_everything" not in fake_analysis
