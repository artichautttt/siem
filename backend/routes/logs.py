from flask import Blueprint, request, jsonify
from database import get_db
from datetime import datetime
from auth import require_role

logs_bp = Blueprint("logs", __name__)

VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
VALID_PROTOCOLS  = {"TCP", "UDP", "ICMP"}
VALID_ACTIONS    = {"ALLOW", "DENY"}


# ── POST /api/logs ─────────────────────────────────────────────────────────────
@logs_bp.route("/logs", methods=["POST"])
@require_role("analyst", "admin")
def create_log():
    """
    Reçoit un événement réseau et le stocke.

    Body JSON attendu :
    {
        "src_ip":   "192.168.1.10",
        "dst_ip":   "10.0.0.1",
        "src_port": 54321,
        "dst_port": 22,
        "protocol": "TCP",
        "action":   "DENY",
        "bytes":    1024,
        "severity": "HIGH",
        "message":  "Tentative de connexion SSH refusée"
    }
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Corps JSON manquant"}), 400

    # Validation des champs obligatoires
    required = ["src_ip", "dst_ip", "dst_port", "protocol", "action"]
    missing  = [f for f in required if f not in data]
    if missing:
        return jsonify({"error": f"Champs manquants : {missing}"}), 400

    # Validation des énumérations
    severity = data.get("severity", "LOW").upper()
    protocol = data.get("protocol", "TCP").upper()
    action   = data.get("action", "ALLOW").upper()

    if severity not in VALID_SEVERITIES:
        return jsonify({"error": f"severity doit être dans {VALID_SEVERITIES}"}), 400
    if protocol not in VALID_PROTOCOLS:
        return jsonify({"error": f"protocol doit être dans {VALID_PROTOCOLS}"}), 400
    if action not in VALID_ACTIONS:
        return jsonify({"error": f"action doit être dans {VALID_ACTIONS}"}), 400

    timestamp = data.get("timestamp", datetime.utcnow().isoformat())

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO logs (timestamp, src_ip, dst_ip, src_port, dst_port,
                          protocol, action, bytes, severity, message)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        timestamp,
        data["src_ip"],
        data["dst_ip"],
        data.get("src_port"),
        data["dst_port"],
        protocol,
        action,
        data.get("bytes", 0),
        severity,
        data.get("message", ""),
    ))
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()

    return jsonify({"message": "Log enregistré", "id": new_id}), 201


# ── GET /api/logs ──────────────────────────────────────────────────────────────
@logs_bp.route("/logs", methods=["GET"])
def get_logs():
    """
    Retourne la liste des logs avec filtres optionnels.

    Query params :
        ?severity=HIGH
        ?protocol=TCP
        ?action=DENY
        ?src_ip=192.168.1.10
        ?limit=50          (défaut : 100)
        ?offset=0          (pour la pagination)
    """
    severity = request.args.get("severity", "").upper()
    protocol = request.args.get("protocol", "").upper()
    action   = request.args.get("action",   "").upper()
    src_ip   = request.args.get("src_ip",   "")
    limit    = min(int(request.args.get("limit",  100)), 500)
    offset   = int(request.args.get("offset", 0))

    query  = "SELECT * FROM logs WHERE 1=1"
    params = []

    if severity and severity in VALID_SEVERITIES:
        query += " AND severity = ?"; params.append(severity)
    if protocol and protocol in VALID_PROTOCOLS:
        query += " AND protocol = ?"; params.append(protocol)
    if action and action in VALID_ACTIONS:
        query += " AND action = ?";   params.append(action)
    if src_ip:
        query += " AND src_ip LIKE ?"; params.append(f"%{src_ip}%")

    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params += [limit, offset]

    conn = get_db()
    rows = conn.execute(query, params).fetchall()
    conn.close()

    return jsonify([dict(r) for r in rows]), 200


# ── GET /api/logs/<id> ─────────────────────────────────────────────────────────
@logs_bp.route("/logs/<int:log_id>", methods=["GET"])
def get_log(log_id):
    """Retourne un log spécifique par son ID."""
    conn = get_db()
    row  = conn.execute("SELECT * FROM logs WHERE id = ?", (log_id,)).fetchone()
    conn.close()

    if row is None:
        return jsonify({"error": "Log introuvable"}), 404
    return jsonify(dict(row)), 200


# ── GET /api/stats ─────────────────────────────────────────────────────────────
@logs_bp.route("/stats", methods=["GET"])
def get_stats():
    """
    Retourne des statistiques globales pour le dashboard.
    Utilisé par le composant Angular StatsCardComponent (Jour 4).
    """
    conn = get_db()

    total      = conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
    by_sev     = conn.execute(
        "SELECT severity, COUNT(*) as count FROM logs GROUP BY severity"
    ).fetchall()
    by_action  = conn.execute(
        "SELECT action, COUNT(*) as count FROM logs GROUP BY action"
    ).fetchall()
    top_src    = conn.execute(
        "SELECT src_ip, COUNT(*) as count FROM logs GROUP BY src_ip ORDER BY count DESC LIMIT 5"
    ).fetchall()
    recent_high = conn.execute(
        "SELECT COUNT(*) FROM logs WHERE severity IN ('HIGH','CRITICAL')"
    ).fetchone()[0]

    conn.close()

    return jsonify({
        "total_logs":        total,
        "high_critical":     recent_high,
        "by_severity":       [dict(r) for r in by_sev],
        "by_action":         [dict(r) for r in by_action],
        "top_source_ips":    [dict(r) for r in top_src],
    }), 200
