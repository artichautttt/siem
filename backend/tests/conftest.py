"""
conftest.py — Fixtures partagées pour les tests backend du Mini-SIEM.

Chaque test tourne sur une base SQLite temporaire (jamais backend/siem.db)
grâce à la variable d'environnement DB_PATH, positionnée AVANT l'import des
modules applicatifs puis rechargés via importlib.
"""
import importlib
import os
import sys

import pytest

# S'assure que backend/ est sur le sys.path (pour "import config", etc.)
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

TEST_API_KEY = "test-api-key"


@pytest.fixture
def app_context(tmp_path, monkeypatch):
    """
    Prépare un environnement de test isolé : DB temporaire, clé API connue,
    CORS par défaut. Recharge les modules applicatifs pour qu'ils prennent en
    compte ces variables (config.py les lit à l'import).

    Retourne le module `app` (Flask) fraîchement rechargé.
    """
    db_path = tmp_path / "test_siem.db"
    monkeypatch.setenv("DB_PATH", str(db_path))
    monkeypatch.setenv("API_KEY", TEST_API_KEY)
    monkeypatch.setenv("CORS_ORIGINS", "http://localhost:4200")
    monkeypatch.setenv("FLASK_DEBUG", "False")

    # Recharge dans l'ordre des dépendances pour propager le nouveau DB_PATH.
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
    importlib.reload(logs_routes)
    importlib.reload(alerts_routes)
    importlib.reload(stats_routes)
    importlib.reload(detection_routes)
    import app as app_module
    importlib.reload(app_module)

    yield app_module


@pytest.fixture
def client(app_context):
    app_context.app.testing = True
    return app_context.app.test_client()
