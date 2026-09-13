"""
wazuh_client.py — Client HTTP pour interroger le Wazuh Indexer (OpenSearch).

Le Wazuh Manager REST (port 55000) ne sert plus les alertes elles-mêmes en
Wazuh 4.x : les alertes sont indexées dans l'Indexer (OpenSearch, port 9200,
index `wazuh-alerts-4.x-*`). Ce module interroge directement cet index et
normalise les documents vers le format d'alerte utilisé par ce projet.
"""
import urllib3

import requests

from config import WAZUH_INDEXER_URL, WAZUH_USER, WAZUH_PASSWORD, WAZUH_VERIFY_SSL, wazuh_level_to_severity

if not WAZUH_VERIFY_SSL:
    # Certificat auto-signé attendu sur une instance de démo locale.
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WazuhUnavailableError(Exception):
    """Levée quand le Wazuh Indexer ne répond pas ou renvoie une erreur."""


def _normalize(hit: dict) -> dict:
    """Convertit un document `wazuh-alerts-*` en alerte au format du projet."""
    src = hit.get("_source", {})
    rule = src.get("rule", {})
    agent = src.get("agent", {})
    data = src.get("data", {})

    level = rule.get("level", 0)
    src_ip = data.get("srcip") or src.get("data", {}).get("src_ip", "")

    return {
        "id":          hit.get("_id"),
        "timestamp":   src.get("timestamp") or src.get("@timestamp"),
        "rule_name":   rule.get("description", "Alerte Wazuh"),
        "src_ip":      src_ip,
        "severity":    wazuh_level_to_severity(level),
        "level":       level,
        "description": rule.get("description", ""),
        "agent":       agent.get("name", ""),
        "mitre":       rule.get("mitre", {}),
        "resolved":    0,
        "source":      "wazuh",
    }


def fetch_alerts(limit: int = 50, min_level: int = 0) -> list[dict]:
    """
    Récupère les alertes les plus récentes depuis l'index `wazuh-alerts-4.x-*`.

    Lève WazuhUnavailableError si l'Indexer est injoignable ou renvoie une
    erreur (instance Wazuh non démarrée, credentials invalides, etc.).
    """
    query = {
        "size": min(limit, 500),
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"range": {"rule.level": {"gte": min_level}}},
    }

    try:
        resp = requests.post(
            f"{WAZUH_INDEXER_URL}/wazuh-alerts-4.x-*/_search",
            json=query,
            auth=(WAZUH_USER, WAZUH_PASSWORD),
            verify=WAZUH_VERIFY_SSL,
            timeout=5,
        )
    except requests.RequestException as exc:
        raise WazuhUnavailableError(f"Wazuh Indexer injoignable : {exc}") from exc

    if resp.status_code != 200:
        raise WazuhUnavailableError(
            f"Wazuh Indexer a renvoyé {resp.status_code} : {resp.text[:200]}"
        )

    hits = resp.json().get("hits", {}).get("hits", [])
    return [_normalize(h) for h in hits]


def check_health() -> bool:
    """Retourne True si le Wazuh Indexer répond correctement."""
    try:
        resp = requests.get(
            f"{WAZUH_INDEXER_URL}/_cluster/health",
            auth=(WAZUH_USER, WAZUH_PASSWORD),
            verify=WAZUH_VERIFY_SSL,
            timeout=5,
        )
        return resp.status_code == 200
    except requests.RequestException:
        return False
