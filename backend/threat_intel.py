"""
threat_intel.py — Enrichissement par flux de threat intelligence externe.

Remplace la liste statique d'IP malveillantes (conservée comme repli) par un
flux public réellement interrogé : blocklist.de "all.txt", des IP ayant
récemment attaqué des serveurs/honeypots, signalées par la communauté (pas
d'authentification requise, mis à jour en continu — ~28 000 IP en pratique).
Mis en cache en mémoire process avec un TTL pour éviter de retélécharger
~28 000 lignes à chaque exécution du moteur de détection.
"""
import time
import logging

import requests

from config import THREAT_INTEL_URL, THREAT_INTEL_TTL_SECONDS, KNOWN_BAD_IPS_FALLBACK

logger = logging.getLogger(__name__)

_cache = {"ips": None, "fetched_at": 0.0, "source": None}


def get_known_bad_ips() -> tuple[set, str]:
    """
    Retourne (ensemble d'IP malveillantes connues, source utilisée).

    Sert le cache s'il est encore valide (THREAT_INTEL_TTL_SECONDS), sinon
    retente un téléchargement ; si celui-ci échoue (réseau, timeout, format
    inattendu), retombe sur KNOWN_BAD_IPS_FALLBACK sans jamais lever
    d'exception — la détection ne doit pas casser si le flux externe est
    indisponible.
    """
    now = time.time()
    if _cache["ips"] is not None and (now - _cache["fetched_at"]) < THREAT_INTEL_TTL_SECONDS:
        return _cache["ips"], _cache["source"]

    try:
        resp = requests.get(THREAT_INTEL_URL, timeout=5)
        resp.raise_for_status()
        ips = {line.strip() for line in resp.text.splitlines() if line.strip()}
        if not ips:
            raise ValueError("flux vide")
        _cache.update(ips=ips, fetched_at=now, source=THREAT_INTEL_URL)
        return ips, THREAT_INTEL_URL
    except Exception as exc:
        logger.warning("Threat intel externe indisponible (%s) — repli sur la liste statique", exc)
        _cache.update(ips=KNOWN_BAD_IPS_FALLBACK, fetched_at=now, source="static-fallback")
        return KNOWN_BAD_IPS_FALLBACK, "static-fallback"
