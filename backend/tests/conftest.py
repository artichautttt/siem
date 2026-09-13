"""
conftest.py — Fixtures partagées pour les tests backend du Mini-SIEM.

Chaque test tourne contre une base PostgreSQL réelle (POSTGRES_* dans
l'environnement — un service Postgres doit déjà tourner, voir README/CI),
avec les tables tronquées avant chaque test pour l'isolation.
"""
import importlib
import os
import sys

import pytest

# S'assure que backend/ est sur le sys.path (pour "import config", etc.)
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

TEST_ADMIN_USERNAME = "test-admin"
TEST_ADMIN_PASSWORD = "test-admin-password"


@pytest.fixture
def app_context(monkeypatch):
    """
    Prépare un environnement de test isolé : tables PostgreSQL tronquées,
    compte admin de test connu, CORS par défaut. Recharge les modules
    applicatifs pour qu'ils prennent en compte ces variables (config.py les
    lit à l'import).

    Retourne le module `app` (Flask) fraîchement rechargé.
    """
    monkeypatch.setenv("ADMIN_USERNAME", TEST_ADMIN_USERNAME)
    monkeypatch.setenv("ADMIN_PASSWORD", TEST_ADMIN_PASSWORD)
    monkeypatch.setenv("JWT_SECRET", "test-jwt-secret")
    monkeypatch.setenv("CORS_ORIGINS", "http://localhost:4200")
    monkeypatch.setenv("FLASK_DEBUG", "False")

    # Recharge dans l'ordre des dépendances pour propager les nouvelles env vars.
    import config
    importlib.reload(config)
    import database
    importlib.reload(database)
    import detector
    importlib.reload(detector)
    import auth
    importlib.reload(auth)
    import routes.logs as logs_routes
    import routes.alerts as alerts_routes
    import routes.stats as stats_routes
    import routes.detection as detection_routes
    import routes.auth_routes as auth_routes
    importlib.reload(logs_routes)
    importlib.reload(alerts_routes)
    importlib.reload(stats_routes)
    importlib.reload(detection_routes)
    importlib.reload(auth_routes)
    import app as app_module
    importlib.reload(app_module)

    # Isolation entre tests : tables déjà créées par app_module (init_db()),
    # on les vide pour repartir d'un état propre à chaque test. init_db()
    # vient de re-semer le compte admin de test (table users vidée => recréé).
    conn = database.get_db()
    conn.execute("TRUNCATE TABLE logs, alerts RESTART IDENTITY")
    conn.execute("TRUNCATE TABLE users RESTART IDENTITY")
    conn.commit()
    conn.close()
    database.init_db()

    yield app_module


@pytest.fixture
def client(app_context):
    app_context.app.testing = True
    return app_context.app.test_client()


@pytest.fixture
def auth_headers(client):
    """Se connecte avec le compte admin de test et retourne le header Bearer."""
    resp = client.post("/api/auth/login", json={
        "username": TEST_ADMIN_USERNAME,
        "password": TEST_ADMIN_PASSWORD,
    })
    token = resp.get_json()["token"]
    return {"Authorization": f"Bearer {token}"}
