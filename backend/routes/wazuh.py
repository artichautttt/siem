"""
routes/wazuh.py — Endpoints exposant les alertes d'une instance Wazuh externe.

Wazuh n'est pas géré par le docker-compose de ce projet : c'est un SIEM/EDR
déployé séparément (voir wazuh-docker/single-node) dont on consomme l'API en
lecture pour enrichir le dashboard avec des alertes réelles, en plus des
alertes générées par le moteur de détection interne.
"""
from flask import Blueprint, request, jsonify

from wazuh_client import fetch_alerts, check_health, WazuhUnavailableError

wazuh_bp = Blueprint("wazuh", __name__)


# ── GET /api/wazuh/alerts ──────────────────────────────────────────────────────
@wazuh_bp.route("/wazuh/alerts", methods=["GET"])
def get_wazuh_alerts():
    """
    Retourne les alertes Wazuh les plus récentes.
    Params : limit (défaut 50, max 500), min_level (défaut 0)
    """
    limit     = min(int(request.args.get("limit", 50)), 500)
    min_level = int(request.args.get("min_level", 0))

    try:
        alerts = fetch_alerts(limit=limit, min_level=min_level)
    except WazuhUnavailableError as exc:
        return jsonify({"error": str(exc), "available": False}), 503

    return jsonify({"alerts": alerts, "total": len(alerts), "available": True}), 200


# ── GET /api/wazuh/health ──────────────────────────────────────────────────────
@wazuh_bp.route("/wazuh/health", methods=["GET"])
def wazuh_health():
    """Indique si l'instance Wazuh (Indexer) est joignable."""
    available = check_health()
    return jsonify({"available": available}), 200 if available else 503
