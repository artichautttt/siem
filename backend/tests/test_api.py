"""
test_api.py — Couvre GET /api/logs, GET /api/alerts et POST /api/detect
(avec et sans clé API valide), sur une DB de test isolée.
"""
from tests.conftest import TEST_API_KEY


def test_get_logs_empty(client):
    resp = client.get("/api/logs")
    assert resp.status_code == 200
    assert resp.get_json() == []


def test_get_alerts_empty(client):
    resp = client.get("/api/alerts")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["alerts"] == []
    assert data["total"] == 0


def test_detect_without_api_key_rejected(client):
    resp = client.post("/api/detect", json={"window_minutes": 60})
    assert resp.status_code == 401
    assert "error" in resp.get_json()


def test_detect_with_invalid_api_key_rejected(client):
    resp = client.post(
        "/api/detect",
        json={"window_minutes": 60},
        headers={"X-API-Key": "wrong-key"},
    )
    assert resp.status_code == 401


def test_detect_with_valid_api_key_accepted(client):
    resp = client.post(
        "/api/detect",
        json={"window_minutes": 60},
        headers={"X-API-Key": TEST_API_KEY},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert "alerts_generated" in data
    assert "risk_score" in data


def test_health_endpoint(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "ok"}
