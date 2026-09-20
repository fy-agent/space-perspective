from fastapi.testclient import TestClient

from core.app.config import Settings
from core.app.main import create_app


def test_health_matches_contract_and_reports_truthful_capabilities(settings: Settings) -> None:
    with TestClient(create_app(settings)) as client:
        response = client.get("/health")

    assert response.status_code == 200
    payload = response.json()
    assert set(payload) == {"status", "version", "db_status", "capabilities", "current_time"}
    assert payload["status"] == "ok"
    assert payload["version"] == "0.1.0"
    assert payload["db_status"] == "ok"
    assert payload["capabilities"] == {
        "real_upload_enabled": False,
        "mock_provider_enabled": True,
        "file_upload_enabled": False,
        "cloud_metadata_analysis_available": False,
        "cloud_metadata_analysis_enabled": False,
        "controlled_synthetic_consent_available": True,
    }
    assert payload["current_time"].endswith("Z")


def test_unknown_route_uses_error_response_shape(settings: Settings) -> None:
    with TestClient(create_app(settings)) as client:
        response = client.get("/not-implemented")

    assert response.status_code == 404
    payload = response.json()
    assert payload["code"] == "HTTP_404"
    assert payload["message"]
    assert payload["request_id"].startswith("req_")
    assert "details" in payload
