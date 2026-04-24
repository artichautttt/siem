"""
routes/stats.py — Endpoints de statistiques avancées pour le dashboard (Jour 3)
"""
from flask import Blueprint, request, jsonify
from database import get_db
from datetime import datetime, timedelta

stats_bp = Blueprint("stats", __name__)


# ── GET /api/stats/timeline ────────────────────────────────────────────────────
@stats_bp.route("/stats/timeline", methods=["GET"])
def get_timeline():
    """
    Retourne le nombre d'événements par heure sur les dernières 24h.
    Utilisé par le graphique de courbe dans Angular (Jour 5).
    """
    conn = get_db()
    rows = conn.execute("""
        SELECT
            strftime('%Y-%m-%dT%H:00:00', timestamp) AS hour,
            COUNT(*) AS total,
            SUM(CASE WHEN action='DENY'  THEN 1 ELSE 0 END) AS denied,
            SUM(CASE WHEN severity IN ('HIGH','CRITICAL') THEN 1 ELSE 0 END) AS threats
        FROM logs
        WHERE timestamp >= datetime('now', '-24 hours')
        GROUP BY hour
        ORDER BY hour ASC
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows]), 200


# ── GET /api/stats/top-ips ─────────────────────────────────────────────────────
@stats_bp.route("/stats/top-ips", methods=["GET"])
def get_top_ips():
    """
    Retourne les IPs sources les plus actives, triées par nombre d'événements.
    Params : limit (défaut 10), action (ALLOW/DENY)
    """
    limit  = min(int(request.args.get("limit", 10)), 50)
    action = request.args.get("action", "").upper()

    query  = """
        SELECT src_ip, COUNT(*) as count,
               SUM(CASE WHEN action='DENY' THEN 1 ELSE 0 END) as denied,
               SUM(CASE WHEN severity IN ('HIGH','CRITICAL') THEN 1 ELSE 0 END) as threats
        FROM logs
    """
    params = []
    if action in {"ALLOW", "DENY"}:
        query += " WHERE action = ?"; params.append(action)

    query += " GROUP BY src_ip ORDER BY count DESC LIMIT ?"
    params.append(limit)

    conn = get_db()
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows]), 200


# ── GET /api/stats/top-ports ───────────────────────────────────────────────────
@stats_bp.route("/stats/top-ports", methods=["GET"])
def get_top_ports():
    """
    Retourne les ports les plus ciblés.
    Params : limit (défaut 10)
    """
    limit = min(int(request.args.get("limit", 10)), 50)
    conn  = get_db()
    rows  = conn.execute("""
        SELECT dst_port, COUNT(*) as count,
               SUM(CASE WHEN action='DENY' THEN 1 ELSE 0 END) as denied
        FROM logs
        GROUP BY dst_port
        ORDER BY count DESC
        LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows]), 200


# ── GET /api/stats/severity-over-time ─────────────────────────────────────────
@stats_bp.route("/stats/severity-over-time", methods=["GET"])
def get_severity_over_time():
    """
    Retourne la distribution des sévérités par heure.
    Utilisé pour le graphique empilé Angular (Jour 5).
    """
    conn = get_db()
    rows = conn.execute("""
        SELECT
            strftime('%Y-%m-%dT%H:00:00', timestamp) AS hour,
            severity,
            COUNT(*) AS count
        FROM logs
        WHERE timestamp >= datetime('now', '-24 hours')
        GROUP BY hour, severity
        ORDER BY hour ASC
    """).fetchall()
    conn.close()

    # Pivot : { hour: { LOW: N, MEDIUM: N, HIGH: N, CRITICAL: N } }
    pivot = {}
    for row in rows:
        h = row["hour"]
        if h not in pivot:
            pivot[h] = {"hour": h, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        pivot[h][row["severity"]] = row["count"]

    return jsonify(list(pivot.values())), 200


# ── GET /api/search ────────────────────────────────────────────────────────────
@stats_bp.route("/search", methods=["GET"])
def search_logs():
    """
    Recherche full-text dans les logs.
    Params : q (terme de recherche), limit, offset
    Cherche dans : src_ip, dst_ip, message, protocol
    """
    q      = request.args.get("q", "").strip()
    limit  = min(int(request.args.get("limit", 50)), 200)
    offset = int(request.args.get("offset", 0))

    if not q:
        return jsonify({"error": "Paramètre 'q' requis"}), 400

    conn = get_db()
    rows = conn.execute("""
        SELECT * FROM logs
        WHERE src_ip    LIKE ?
           OR dst_ip    LIKE ?
           OR message   LIKE ?
           OR protocol  LIKE ?
           OR CAST(dst_port AS TEXT) LIKE ?
        ORDER BY id DESC
        LIMIT ? OFFSET ?
    """, [f"%{q}%"] * 5 + [limit, offset]).fetchall()

    total = conn.execute("""
        SELECT COUNT(*) FROM logs
        WHERE src_ip    LIKE ?
           OR dst_ip    LIKE ?
           OR message   LIKE ?
           OR protocol  LIKE ?
           OR CAST(dst_port AS TEXT) LIKE ?
    """, [f"%{q}%"] * 5).fetchone()[0]

    conn.close()
    return jsonify({
        "results": [dict(r) for r in rows],
        "total":   total,
        "query":   q,
    }), 200
