"""
auth.py — Authentification minimale par clé API pour le Mini-SIEM.

Protège les endpoints d'écriture (création/modification/suppression) via
un header `X-API-Key` comparé à la variable d'environnement API_KEY
(voir config.py). Les endpoints de lecture restent ouverts pour la démo.
"""
from functools import wraps
from flask import request, jsonify

from config import API_KEY


def require_api_key(view_func):
    """Décorateur : exige un header X-API-Key valide, sinon 401 JSON."""

    @wraps(view_func)
    def wrapper(*args, **kwargs):
        provided = request.headers.get("X-API-Key", "")
        if not provided or provided != API_KEY:
            return jsonify({"error": "Clé API manquante ou invalide"}), 401
        return view_func(*args, **kwargs)

    return wrapper
