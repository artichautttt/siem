"""
routes/alerts.py — Endpoints pour la gestion des alertes (Jour 3)
"""
from flask import Blueprint, request, jsonify
from database import get_db
from datetime import datetime
from auth import require_api_key

alerts_bp = Blueprint("alerts", __name__)


# ── POST /api/alerts ───────────────────────────────────────────────────────────
@alerts_bp.route("/alerts", methods=["POST"])
@require_api_key
def create_alert():
    """Crée une alerte manuellement."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Corps JSON manquant"}), 400

    required = ["rule_name", "severity"]
    missing  = [f for f in required if f not in data]
    if missing:
        return jsonify({"error": f"Champs manquants : {missing}"}), 400

    if data["severity"].upper() not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        return jsonify({"error": "Sévérité invalide"}), 400

    conn   = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO alerts (timestamp, rule_name, src_ip, severity, description, resolved)
        VALUES (?, ?, ?, ?, ?, 0)
    """, (
        data.get("timestamp", datetime.utcnow().isoformat()),
        data["rule_name"],
        data.get("src_ip", ""),
        data["severity"].upper(),
        data.get("description", ""),
    ))
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()

    return jsonify({"message": "Alerte créée", "id": new_id}), 201


# ── GET /api/alerts ────────────────────────────────────────────────────────────
@alerts_bp.route("/alerts", methods=["GET"])
def get_alerts():
    """
    Retourne les alertes avec filtres.
    Params : severity, resolved (0/1), limit, offset
    """
    severity = request.args.get("severity", "").upper()
    resolved = request.args.get("resolved", "")
    limit    = min(int(request.args.get("limit",  50)), 200)
    offset   = int(request.args.get("offset", 0))

    query  = "SELECT * FROM alerts WHERE 1=1"
    params = []

    if severity in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        query += " AND severity = ?"; params.append(severity)
    if resolved in {"0", "1"}:
        query += " AND resolved = ?"; params.append(int(resolved))

    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params += [limit, offset]

    conn = get_db()
    rows = conn.execute(query, params).fetchall()
    total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    open_ = conn.execute("SELECT COUNT(*) FROM alerts WHERE resolved=0").fetchone()[0]
    conn.close()

    return jsonify({
        "alerts":       [dict(r) for r in rows],
        "total":        total,
        "open":         open_,
        "resolved":     total - open_,
    }), 200


# ── PATCH /api/alerts/<id>/resolve ─────────────────────────────────────────────
@alerts_bp.route("/alerts/<int:alert_id>/resolve", methods=["PATCH"])
@require_api_key
def resolve_alert(alert_id):
    """Marque une alerte comme résolue."""
    conn = get_db()
    row  = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
    if row is None:
        conn.close()
        return jsonify({"error": "Alerte introuvable"}), 404

    conn.execute("UPDATE alerts SET resolved=1 WHERE id=?", (alert_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": f"Alerte #{alert_id} résolue"}), 200


# ── DELETE /api/alerts/<id> ────────────────────────────────────────────────────
@alerts_bp.route("/alerts/<int:alert_id>", methods=["DELETE"])
@require_api_key
def delete_alert(alert_id):
    """Supprime une alerte."""
    conn = get_db()
    row  = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
    if row is None:
        conn.close()
        return jsonify({"error": "Alerte introuvable"}), 404

    conn.execute("DELETE FROM alerts WHERE id=?", (alert_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": f"Alerte #{alert_id} supprimée"}), 200
