"""
auth.py — Authentification JWT multi-rôle pour le Mini-SIEM.

Remplace l'ancienne clé API unique partagée. Deux rôles :
    - "analyst" : ingérer des logs, lancer une détection, résoudre des alertes
    - "admin"   : tout ce que peut faire "analyst", plus supprimer des
      alertes et gérer les comptes utilisateurs

Les tokens sont émis par POST /api/auth/login (voir routes/auth_routes.py)
et doivent être envoyés en header `Authorization: Bearer <token>`.
"""
from functools import wraps
from datetime import datetime, timedelta, timezone

import jwt
from flask import request, jsonify

from config import JWT_SECRET, JWT_EXPIRY_HOURS

ROLES = {"analyst", "admin"}


def create_token(username: str, role: str) -> str:
    payload = {
        "sub": username,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRY_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def require_role(*allowed_roles):
    """Décorateur : exige un JWT valide, et si `allowed_roles` est fourni,
    que le rôle du token en fasse partie. Attache le payload à `request.user`."""

    def decorator(view_func):
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            header = request.headers.get("Authorization", "")
            if not header.startswith("Bearer "):
                return jsonify({"error": "Authentification requise"}), 401

            token = header[len("Bearer "):]
            try:
                payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            except jwt.ExpiredSignatureError:
                return jsonify({"error": "Session expirée"}), 401
            except jwt.InvalidTokenError:
                return jsonify({"error": "Token invalide"}), 401

            if allowed_roles and payload.get("role") not in allowed_roles:
                return jsonify({"error": "Droits insuffisants pour cette action"}), 403

            request.user = payload
            return view_func(*args, **kwargs)

        return wrapper

    return decorator
