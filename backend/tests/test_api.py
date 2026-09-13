"""
test_api.py — Couvre GET /api/logs, GET /api/alerts et POST /api/detect
(avec et sans JWT valide), sur une DB de test isolée.
"""


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


def test_detect_without_token_rejected(client):
    resp = client.post("/api/detect", json={"window_minutes": 60})
    assert resp.status_code == 401
    assert "error" in resp.get_json()


def test_detect_with_invalid_token_rejected(client):
    resp = client.post(
        "/api/detect",
        json={"window_minutes": 60},
        headers={"Authorization": "Bearer not-a-real-token"},
    )
    assert resp.status_code == 401


def test_detect_with_valid_token_accepted(client, auth_headers):
    resp = client.post(
        "/api/detect",
        json={"window_minutes": 60},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert "alerts_generated" in data
    assert "risk_score" in data


def test_health_endpoint(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "ok"}


def test_login_wrong_password_rejected(client):
    resp = client.post("/api/auth/login", json={"username": "test-admin", "password": "wrong"})
    assert resp.status_code == 401


def test_login_correct_password_returns_token(client, auth_headers):
    resp = client.get("/api/auth/me", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["username"] == "test-admin"
    assert data["role"] == "admin"


def test_analyst_cannot_delete_alert(client, auth_headers):
    # Crée un analyste, se connecte avec, tente de supprimer une alerte
    client.post("/api/auth/users",
                json={"username": "an1", "password": "an1-password", "role": "analyst"},
                headers=auth_headers)
    login = client.post("/api/auth/login", json={"username": "an1", "password": "an1-password"})
    analyst_headers = {"Authorization": f"Bearer {login.get_json()['token']}"}

    resp = client.delete("/api/alerts/1", headers=analyst_headers)
    assert resp.status_code == 403
