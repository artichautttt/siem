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

TEST_API_KEY = "test-api-key"


@pytest.fixture
def app_context(monkeypatch):
    """
    Prépare un environnement de test isolé : tables PostgreSQL tronquées,
    clé API connue, CORS par défaut. Recharge les modules applicatifs pour
    qu'ils prennent en compte ces variables (config.py les lit à l'import).

    Retourne le module `app` (Flask) fraîchement rechargé.
    """
    monkeypatch.setenv("API_KEY", TEST_API_KEY)
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
    importlib.reload(logs_routes)
    importlib.reload(alerts_routes)
    importlib.reload(stats_routes)
    importlib.reload(detection_routes)
    import app as app_module
    importlib.reload(app_module)

    # Isolation entre tests : tables déjà créées par app_module (init_db()),
    # on les vide pour repartir d'un état propre à chaque test.
    conn = database.get_db()
    conn.execute("TRUNCATE TABLE logs, alerts RESTART IDENTITY")
    conn.commit()
    conn.close()

    yield app_module


@pytest.fixture
def client(app_context):
    app_context.app.testing = True
    return app_context.app.test_client()
