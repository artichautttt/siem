"""
parser.py — Parseur et enrichisseur de logs réseau pour le Mini-SIEM.

Rôle :
    - Valider et normaliser les logs entrants (depuis l'API ou le générateur)
    - Enrichir chaque log avec des métadonnées utiles (géo IP, classification)
    - Détecter automatiquement la sévérité si non fournie

Usage :
    from parser import LogParser
    parser = LogParser()
    enriched = parser.parse(raw_log_dict)
"""
from datetime import datetime
from typing import Optional
import ipaddress


# ── Classification des ports ──────────────────────────────────────────────────
PORT_RISK = {
    # Port  : (service, sévérité par défaut si DENY)
    22:   ("SSH",        "HIGH"),
    23:   ("Telnet",     "CRITICAL"),
    21:   ("FTP",        "MEDIUM"),
    25:   ("SMTP",       "MEDIUM"),
    53:   ("DNS",        "LOW"),
    80:   ("HTTP",       "LOW"),
    443:  ("HTTPS",      "LOW"),
    445:  ("SMB",        "CRITICAL"),
    3306: ("MySQL",      "HIGH"),
    3389: ("RDP",        "CRITICAL"),
    5432: ("PostgreSQL", "HIGH"),
    6379: ("Redis",      "HIGH"),
    8080: ("HTTP-Alt",   "LOW"),
    8443: ("HTTPS-Alt",  "LOW"),
    27017:("MongoDB",    "HIGH"),
}

# IPs connues comme malveillantes (liste simplifiée pour la démo)
KNOWN_BAD_IPS = {
    "45.33.32.156",   # Shodan scanner
    "198.51.100.5",   # Test range (RFC 5737)
    "203.0.113.42",   # Test range (RFC 5737)
}

# Plages IP internes (RFC 1918)
PRIVATE_RANGES = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
]


class LogParser:
    """
    Parse, valide et enrichit les logs réseau bruts.
    """

    # ── Validation ─────────────────────────────────────────────────────────────
    def _validate(self, raw: dict) -> tuple[bool, str]:
        """Retourne (is_valid, error_message)."""
        required = ["src_ip", "dst_ip", "dst_port", "protocol", "action"]
        for field in required:
            if field not in raw or raw[field] is None:
                return False, f"Champ obligatoire manquant : {field}"

        # Validation IP
        for ip_field in ["src_ip", "dst_ip"]:
            try:
                ipaddress.IPv4Address(raw[ip_field])
            except ValueError:
                return False, f"IP invalide : {raw[ip_field]}"

        # Validation port
        port = raw.get("dst_port")
        if not isinstance(port, int) or not (0 < port <= 65535):
            return False, f"Port invalide : {port}"

        # Validation protocole
        if raw.get("protocol", "").upper() not in {"TCP", "UDP", "ICMP"}:
            return False, f"Protocole invalide : {raw.get('protocol')}"

        # Validation action
        if raw.get("action", "").upper() not in {"ALLOW", "DENY"}:
            return False, f"Action invalide : {raw.get('action')}"

        return True, ""

    # ── Classification IP ──────────────────────────────────────────────────────
    def _is_private_ip(self, ip: str) -> bool:
        try:
            addr = ipaddress.IPv4Address(ip)
            return any(addr in net for net in PRIVATE_RANGES)
        except ValueError:
            return False

    def _classify_ip(self, ip: str) -> str:
        """Retourne INTERNAL / EXTERNAL / KNOWN_BAD."""
        if ip in KNOWN_BAD_IPS:
            return "KNOWN_BAD"
        if self._is_private_ip(ip):
            return "INTERNAL"
        return "EXTERNAL"

    # ── Détection de sévérité ─────────────────────────────────────────────────
    def _infer_severity(self, raw: dict) -> str:
        """
        Déduit la sévérité si non fournie, selon :
        - Le port de destination
        - L'action (DENY toujours plus grave qu'ALLOW)
        - La classification de l'IP source
        - Le volume de données
        """
        action   = raw.get("action", "ALLOW").upper()
        port     = raw.get("dst_port", 0)
        src_type = self._classify_ip(raw.get("src_ip", ""))
        bytes_   = raw.get("bytes", 0)

        # IP connue malveillante → au moins HIGH
        if src_type == "KNOWN_BAD":
            return "CRITICAL" if action == "DENY" else "HIGH"

        # Port à risque critique
        if port in [23, 445, 3389]:
            return "CRITICAL" if action == "DENY" else "HIGH"

        # Port à risque élevé
        if port in [22, 3306, 5432, 6379, 27017] and action == "DENY":
            return "HIGH"

        # Volume anormal (> 1MB) sur trafic autorisé = possible exfiltration
        if action == "ALLOW" and bytes_ > 1_000_000:
            return "HIGH"

        # Port à risque moyen
        if port in [21, 25] and action == "DENY":
            return "MEDIUM"

        # Trafic normal
        return "LOW"

    # ── Normalisation timestamp ───────────────────────────────────────────────
    def _normalize_timestamp(self, ts: Optional[str]) -> str:
        if not ts:
            return datetime.utcnow().isoformat()
        # Accepte plusieurs formats
        for fmt in ["%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S",
                    "%Y-%m-%dT%H:%M:%S.%f", "%d/%m/%Y %H:%M:%S"]:
            try:
                return datetime.strptime(ts, fmt).isoformat()
            except ValueError:
                continue
        return datetime.utcnow().isoformat()

    # ── Enrichissement ─────────────────────────────────────────────────────────
    def _enrich(self, raw: dict) -> dict:
        """Ajoute des métadonnées calculées au log."""
        port     = raw.get("dst_port", 0)
        src_ip   = raw.get("src_ip", "")
        action   = raw.get("action", "ALLOW").upper()

        service_name, _ = PORT_RISK.get(port, (f"PORT-{port}", "LOW"))
        src_type = self._classify_ip(src_ip)

        # Direction du flux
        src_internal = self._is_private_ip(src_ip)
        dst_internal = self._is_private_ip(raw.get("dst_ip", ""))
        if src_internal and dst_internal:
            direction = "INTERNAL→INTERNAL"
        elif src_internal and not dst_internal:
            direction = "INTERNAL→EXTERNAL"
        elif not src_internal and dst_internal:
            direction = "EXTERNAL→INTERNAL"
        else:
            direction = "EXTERNAL→EXTERNAL"

        # Message auto si non fourni
        if not raw.get("message"):
            verb = "autorisé" if action == "ALLOW" else "bloqué"
            raw["message"] = f"Trafic {service_name} {verb} ({direction})"

        # Catégorie automatique si non fournie
        if not raw.get("category"):
            if src_type == "KNOWN_BAD":
                raw["category"] = "THREAT"
            elif action == "DENY" and port in PORT_RISK:
                raw["category"] = "SUSPICIOUS"
            else:
                raw["category"] = "NORMAL"

        raw["service"]   = service_name
        raw["src_type"]  = src_type
        raw["direction"] = direction

        return raw

    # ── Interface publique ─────────────────────────────────────────────────────
    def parse(self, raw: dict) -> tuple[dict, bool, str]:
        """
        Parse et enrichit un log brut.

        Returns:
            (enriched_log, is_valid, error_message)
        """
        is_valid, error = self._validate(raw)
        if not is_valid:
            return {}, False, error

        # Normalise les champs
        raw["protocol"] = raw.get("protocol", "TCP").upper()
        raw["action"]   = raw.get("action", "ALLOW").upper()
        raw["bytes"]    = raw.get("bytes", 0)
        raw["timestamp"] = self._normalize_timestamp(raw.get("timestamp"))

        # Sévérité : utilise celle fournie ou la calcule
        provided_severity = raw.get("severity", "").upper()
        if provided_severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raw["severity"] = self._infer_severity(raw)

        # Enrichissement
        raw = self._enrich(raw)

        return raw, True, ""

    def parse_batch(self, raws: list[dict]) -> tuple[list[dict], list[str]]:
        """
        Parse une liste de logs.

        Returns:
            (valid_logs, errors)
        """
        valid  = []
        errors = []
        for i, raw in enumerate(raws):
            parsed, ok, err = self.parse(raw)
            if ok:
                valid.append(parsed)
            else:
                errors.append(f"Log #{i+1} invalide : {err}")
        return valid, errors
