"""
routes/detection.py — Endpoint Flask pour le moteur de détection (Jour 7)
"""
from flask import Blueprint, request, jsonify
from detector import DetectionEngine

detection_bp = Blueprint("detection", __name__)


# ── POST /api/detect ───────────────────────────────────────────────────────────
@detection_bp.route("/detect", methods=["POST"])
def run_detection():
    """
    Lance le moteur de détection manuellement.
    Body JSON optionnel : { "window_minutes": 60 }
    """
    data    = request.get_json(silent=True) or {}
    window  = data.get("window_minutes", 5)

    engine  = DetectionEngine(window_minutes=window)
    result  = engine.run()

    return jsonify(result), 200


# ── GET /api/detect/score ──────────────────────────────────────────────────────
@detection_bp.route("/detect/score", methods=["GET"])
def get_risk_score():
    """
    Retourne uniquement le score de risque global (pour le dashboard).
    Param : ?window=60 (minutes, défaut 5)
    """
    window = int(request.args.get("window", 5))
    engine = DetectionEngine(window_minutes=window)
    score  = engine.compute_risk_score()
    return jsonify(score), 200
