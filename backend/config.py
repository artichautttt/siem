"""
config.py — Configuration centralisée et constantes partagées du Mini-SIEM.

Regroupe :
    - Les paramètres lus depuis l'environnement (.env) : port, chemin DB,
      origines CORS, clé API, mode debug.
    - Les constantes métier auparavant dupliquées dans detector.py, parser.py
      et generator.py : IPs connues malveillantes, ports critiques/à risque,
      mapping service <-> port.
"""
import os

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # python-dotenv non installé (ex: environnement minimal) : on continue
    # avec les seules variables d'environnement déjà présentes.
    pass


# ── Paramètres d'exécution ─────────────────────────────────────────────────────
PORT = int(os.environ.get("PORT", 5000))
FLASK_DEBUG = os.environ.get("FLASK_DEBUG", "False").lower() in {"1", "true", "yes"}

# ── Base de données (PostgreSQL) ────────────────────────────────────────────────
# Remplace le SQLite d'origine. "postgres" est le nom de service utilisé aussi
# bien par docker-compose que par le Service Kubernetes du même nom.
POSTGRES_HOST     = os.environ.get("POSTGRES_HOST", "postgres")
POSTGRES_PORT     = int(os.environ.get("POSTGRES_PORT", 5432))
POSTGRES_DB       = os.environ.get("POSTGRES_DB", "minisiem")
POSTGRES_USER     = os.environ.get("POSTGRES_USER", "minisiem")
POSTGRES_PASSWORD = os.environ.get("POSTGRES_PASSWORD", "minisiem")

CORS_ORIGINS = [
    o.strip() for o in os.environ.get("CORS_ORIGINS", "http://localhost:4200").split(",")
    if o.strip()
]

# Clé API utilisée pour protéger les endpoints d'écriture (header X-API-Key).
# Valeur par défaut fournie UNIQUEMENT pour le développement local — à changer
# impérativement en environnement partagé/prod via la variable API_KEY.
API_KEY = os.environ.get("API_KEY", "change-me")

# ── Intégration Wazuh (optionnelle) ────────────────────────────────────────────
# Le Wazuh Indexer (OpenSearch) expose les alertes réelles sur son API HTTPS.
# Instance déployée séparément (voir wazuh-docker/single-node), non gérée par
# le docker-compose de ce projet.
WAZUH_INDEXER_URL = os.environ.get("WAZUH_INDEXER_URL", "https://localhost:9200")
WAZUH_USER         = os.environ.get("WAZUH_USER", "admin")
WAZUH_PASSWORD     = os.environ.get("WAZUH_PASSWORD", "SecretPassword")
# Certificat auto-signé par défaut sur une instance locale de démo -> désactivé.
WAZUH_VERIFY_SSL   = os.environ.get("WAZUH_VERIFY_SSL", "False").lower() in {"1", "true", "yes"}


# ── Constantes métier partagées ────────────────────────────────────────────────

# IPs connues comme malveillantes (liste simplifiée pour la démo pédagogique).
KNOWN_BAD_IPS = {
    "45.33.32.156",   # Shodan scanner
    "198.51.100.5",   # Test range (RFC 5737)
    "203.0.113.42",   # Test range (RFC 5737)
}

# Ports critiques (services historiquement vulnérables : Telnet, SMB, RDP).
CRITICAL_PORTS = {23, 445, 3389}

# Ports à risque élevé (SSH, bases de données exposées).
HIGH_PORTS = {22, 3306, 5432, 6379, 27017}

# Classification service/sévérité par port, utilisée par le parser pour
# enrichir les logs et déduire une sévérité par défaut.
PORT_RISK = {
    22:    ("SSH",        "HIGH"),
    23:    ("Telnet",     "CRITICAL"),
    21:    ("FTP",        "MEDIUM"),
    25:    ("SMTP",       "MEDIUM"),
    53:    ("DNS",        "LOW"),
    80:    ("HTTP",       "LOW"),
    443:   ("HTTPS",      "LOW"),
    445:   ("SMB",        "CRITICAL"),
    3306:  ("MySQL",      "HIGH"),
    3389:  ("RDP",        "CRITICAL"),
    5432:  ("PostgreSQL", "HIGH"),
    6379:  ("Redis",      "HIGH"),
    8080:  ("HTTP-Alt",   "LOW"),
    8443:  ("HTTPS-Alt",  "LOW"),
    27017: ("MongoDB",    "HIGH"),
}

# Nom du service associé à chaque port critique (utilisé par detector.py).
CRITICAL_SERVICE_NAMES = {23: "Telnet", 445: "SMB", 3389: "RDP"}

# ── Mapping MITRE ATT&CK des règles de détection ───────────────────────────────
MITRE_MAPPING = {
    "Brute Force SSH": {
        "technique_id":   "T1110",
        "technique_name": "Brute Force",
        "tactic":         "Credential Access",
    },
    "Port Scan": {
        "technique_id":   "T1595",
        "technique_name": "Active Scanning",
        "tactic":         "Reconnaissance",
    },
    "Volume Anormal": {
        "technique_id":   "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "tactic":         "Exfiltration",
    },
    "Accès Telnet Critique": {
        "technique_id":   "T1021",
        "technique_name": "Remote Services",
        "tactic":         "Lateral Movement",
    },
    "Accès SMB Critique": {
        "technique_id":   "T1021.002",
        "technique_name": "Remote Services: SMB/Windows Admin Shares",
        "tactic":         "Lateral Movement",
    },
    "Accès RDP Critique": {
        "technique_id":   "T1021.001",
        "technique_name": "Remote Services: Remote Desktop Protocol",
        "tactic":         "Lateral Movement",
    },
    "IP Malveillante Connue": {
        "technique_id":   "T1590",
        "technique_name": "Gather Victim Network Information",
        "tactic":         "Reconnaissance",
    },
}

# Mapping du niveau de règle Wazuh (0-15, voir doc Wazuh "Rule classification")
# vers les 4 niveaux de sévérité utilisés dans ce projet, pour un affichage
# cohérent entre alertes internes et alertes Wazuh.
def wazuh_level_to_severity(level: int) -> str:
    if level >= 12:
        return "CRITICAL"
    if level >= 7:
        return "HIGH"
    if level >= 4:
        return "MEDIUM"
    return "LOW"
