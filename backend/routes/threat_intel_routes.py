"""
routes/threat_intel_routes.py — Statut du flux de threat intelligence externe.
"""
from flask import Blueprint, jsonify

from threat_intel import get_known_bad_ips

threat_intel_bp = Blueprint("threat_intel", __name__)


# ── GET /api/threat-intel/status ───────────────────────────────────────────────
@threat_intel_bp.route("/threat-intel/status", methods=["GET"])
def status():
    """Déclenche (ou sert depuis le cache) le flux et retourne son statut."""
    ips, source = get_known_bad_ips()
    return jsonify({
        "source": source,
        "count": len(ips),
        "using_fallback": source == "static-fallback",
    }), 200
