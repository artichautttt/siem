"""
routes/auth_routes.py — Connexion et gestion des comptes utilisateurs.
"""
from flask import Blueprint, request, jsonify
from werkzeug.security import check_password_hash, generate_password_hash

from database import get_db
from auth import create_token, require_role, ROLES

auth_bp = Blueprint("auth", __name__)


# ── POST /api/auth/login ───────────────────────────────────────────────────────
@auth_bp.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()

    if row is None or not check_password_hash(row["password_hash"], password):
        return jsonify({"error": "Identifiants invalides"}), 401

    token = create_token(row["username"], row["role"])
    return jsonify({"token": token, "username": row["username"], "role": row["role"]}), 200


# ── GET /api/auth/me ───────────────────────────────────────────────────────────
@auth_bp.route("/auth/me", methods=["GET"])
@require_role()
def me():
    return jsonify({"username": request.user["sub"], "role": request.user["role"]}), 200


# ── GET /api/auth/users (admin) ────────────────────────────────────────────────
@auth_bp.route("/auth/users", methods=["GET"])
@require_role("admin")
def list_users():
    conn = get_db()
    rows = conn.execute("SELECT id, username, role FROM users ORDER BY id").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows]), 200


# ── POST /api/auth/users (admin) ───────────────────────────────────────────────
@auth_bp.route("/auth/users", methods=["POST"])
@require_role("admin")
def create_user():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    role = data.get("role", "analyst")

    if not username or not password:
        return jsonify({"error": "username et password requis"}), 400
    if role not in ROLES:
        return jsonify({"error": f"role doit être l'un de {sorted(ROLES)}"}), 400

    conn = get_db()
    existing = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if existing is not None:
        conn.close()
        return jsonify({"error": "Ce nom d'utilisateur existe déjà"}), 409

    conn.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        (username, generate_password_hash(password), role),
    )
    conn.commit()
    conn.close()
    return jsonify({"message": f"Utilisateur '{username}' créé", "role": role}), 201


# ── DELETE /api/auth/users/<id> (admin) ────────────────────────────────────────
@auth_bp.route("/auth/users/<int:user_id>", methods=["DELETE"])
@require_role("admin")
def delete_user(user_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        conn.close()
        return jsonify({"error": "Utilisateur introuvable"}), 404
    if row["username"] == request.user["sub"]:
        conn.close()
        return jsonify({"error": "Impossible de supprimer son propre compte"}), 400

    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Utilisateur supprimé"}), 200
