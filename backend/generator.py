"""
generator.py — Générateur de logs réseau réalistes pour le Mini-SIEM
Simule différents scénarios d'attaque et de trafic normal.

Usage :
    from generator import LogGenerator
    gen = LogGenerator()
    log = gen.generate()          # un seul log
    logs = gen.generate_batch(50) # 50 logs
"""
import random
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from typing import Optional


# ── Modèle de données ─────────────────────────────────────────────────────────
@dataclass
class LogEntry:
    timestamp:  str
    src_ip:     str
    dst_ip:     str
    src_port:   int
    dst_port:   int
    protocol:   str
    action:     str
    bytes:      int
    severity:   str
    message:    str
    category:   str   # NOUVEAU : type d'événement pour le dashboard

    def to_dict(self):
        return asdict(self)


# ── Données de simulation ─────────────────────────────────────────────────────
INTERNAL_SUBNET = [f"192.168.1.{i}" for i in range(1, 30)]
EXTERNAL_IPS = [
    "45.33.32.156",    # IP connue pour du scanning
    "198.51.100.5",
    "203.0.113.42",
    "91.108.4.10",     # Telegram (souvent filtré en entreprise)
    "8.8.8.8",         # Google DNS
    "1.1.1.1",         # Cloudflare DNS
    "172.217.18.46",   # Google
    "13.32.99.240",    # AWS CloudFront
]

# Services réseau courants avec leurs caractéristiques
SERVICES = {
    22:   {"name": "SSH",   "protocol": "TCP", "risk": "high"},
    80:   {"name": "HTTP",  "protocol": "TCP", "risk": "low"},
    443:  {"name": "HTTPS", "protocol": "TCP", "risk": "low"},
    3306: {"name": "MySQL", "protocol": "TCP", "risk": "high"},
    5432: {"name": "PostgreSQL", "protocol": "TCP", "risk": "high"},
    3389: {"name": "RDP",   "protocol": "TCP", "risk": "critical"},
    21:   {"name": "FTP",   "protocol": "TCP", "risk": "medium"},
    25:   {"name": "SMTP",  "protocol": "TCP", "risk": "medium"},
    53:   {"name": "DNS",   "protocol": "UDP", "risk": "low"},
    8080: {"name": "HTTP-Alt", "protocol": "TCP", "risk": "low"},
    445:  {"name": "SMB",   "protocol": "TCP", "risk": "critical"},
    6379: {"name": "Redis", "protocol": "TCP", "risk": "high"},
}


# ── Scénarios d'attaque ───────────────────────────────────────────────────────
class AttackScenario:
    """Génère des séquences de logs simulant une attaque réelle."""

    @staticmethod
    def brute_force_ssh(src_ip: str, dst_ip: str, count: int = 5) -> list[dict]:
        """Simule une attaque brute force SSH : N tentatives rapprochées."""
        logs = []
        base_time = datetime.utcnow() - timedelta(minutes=random.randint(1, 10))
        for i in range(count):
            ts = (base_time + timedelta(seconds=i * random.randint(3, 8))).isoformat()
            severity = "CRITICAL" if i >= 4 else "HIGH"
            logs.append({
                "timestamp": ts,
                "src_ip":    src_ip,
                "dst_ip":    dst_ip,
                "src_port":  random.randint(1024, 65535),
                "dst_port":  22,
                "protocol":  "TCP",
                "action":    "DENY",
                "bytes":     random.randint(64, 256),
                "severity":  severity,
                "message":   f"Brute force SSH — tentative {i+1}/{count}",
                "category":  "BRUTE_FORCE",
            })
        return logs

    @staticmethod
    def port_scan(src_ip: str, dst_ip: str) -> list[dict]:
        """Simule un scan de ports : tentatives sur de nombreux ports en peu de temps."""
        ports = random.sample(list(SERVICES.keys()) + list(range(1, 1024)), 15)
        logs = []
        base_time = datetime.utcnow() - timedelta(minutes=random.randint(1, 5))
        for i, port in enumerate(ports):
            ts = (base_time + timedelta(seconds=i * 0.5)).isoformat()
            logs.append({
                "timestamp": ts,
                "src_ip":    src_ip,
                "dst_ip":    dst_ip,
                "src_port":  random.randint(1024, 65535),
                "dst_port":  port,
                "protocol":  "TCP",
                "action":    "DENY",
                "bytes":     64,
                "severity":  "HIGH",
                "message":   f"Port scan détecté — port {port}",
                "category":  "PORT_SCAN",
            })
        return logs

    @staticmethod
    def data_exfiltration(src_ip: str, dst_ip: str) -> list[dict]:
        """Simule une exfiltration de données : gros volumes sortants inhabituels."""
        logs = []
        base_time = datetime.utcnow() - timedelta(minutes=random.randint(5, 30))
        for i in range(random.randint(3, 6)):
            ts = (base_time + timedelta(minutes=i * 2)).isoformat()
            logs.append({
                "timestamp": ts,
                "src_ip":    src_ip,
                "dst_ip":    dst_ip,
                "src_port":  random.randint(1024, 65535),
                "dst_port":  random.choice([80, 443, 8080]),
                "protocol":  "TCP",
                "action":    "ALLOW",   # Trafic autorisé mais suspect (volume)
                "bytes":     random.randint(500_000, 5_000_000),  # 500KB–5MB
                "severity":  "HIGH",
                "message":   f"Volume de données sortant anormal — {i+1}ère transmission",
                "category":  "EXFILTRATION",
            })
        return logs


# ── Générateur principal ──────────────────────────────────────────────────────
class LogGenerator:
    """
    Génère des logs réseau réalistes avec une distribution probabiliste.
    80% trafic normal, 20% trafic suspect/malveillant.
    """

    def __init__(self):
        self.attack = AttackScenario()

    def _random_timestamp(self, minutes_back: int = 120) -> str:
        delta = timedelta(
            minutes=random.randint(0, minutes_back),
            seconds=random.randint(0, 59),
        )
        return (datetime.utcnow() - delta).isoformat()

    def _normal_traffic(self) -> dict:
        """Génère un log de trafic réseau normal."""
        port = random.choice([80, 443, 53, 8080])
        svc  = SERVICES[port]
        src  = random.choice(INTERNAL_SUBNET)
        dst  = random.choice(INTERNAL_SUBNET + EXTERNAL_IPS[:4])

        return {
            "timestamp": self._random_timestamp(),
            "src_ip":    src,
            "dst_ip":    dst,
            "src_port":  random.randint(1024, 65535),
            "dst_port":  port,
            "protocol":  svc["protocol"],
            "action":    "ALLOW",
            "bytes":     random.randint(200, 50_000),
            "severity":  "LOW",
            "message":   f"Trafic {svc['name']} normal",
            "category":  "NORMAL",
        }

    def _suspicious_traffic(self) -> dict:
        """Génère un log de trafic suspect (hors attaque structurée)."""
        port = random.choice([22, 3306, 5432, 3389, 21, 25, 445, 6379])
        svc  = SERVICES[port]
        risk = svc["risk"]

        severity_map = {"low": "LOW", "medium": "MEDIUM",
                        "high": "HIGH", "critical": "CRITICAL"}
        severity = severity_map.get(risk, "MEDIUM")

        src = random.choice(EXTERNAL_IPS)
        dst = random.choice(INTERNAL_SUBNET)

        messages = {
            22:   "Tentative de connexion SSH depuis IP externe",
            3306: "Accès MySQL bloqué depuis IP externe",
            5432: "Accès PostgreSQL bloqué depuis IP externe",
            3389: "Tentative RDP bloquée",
            21:   "Tentative FTP non autorisée",
            25:   "Tentative SMTP suspecte",
            445:  "Tentative accès SMB depuis IP externe — risque ransomware",
            6379: "Accès Redis non authentifié bloqué",
        }

        return {
            "timestamp": self._random_timestamp(),
            "src_ip":    src,
            "dst_ip":    dst,
            "src_port":  random.randint(1024, 65535),
            "dst_port":  port,
            "protocol":  svc["protocol"],
            "action":    "DENY",
            "bytes":     random.randint(64, 2048),
            "severity":  severity,
            "message":   messages.get(port, f"Accès {svc['name']} bloqué"),
            "category":  "SUSPICIOUS",
        }

    def generate(self) -> dict:
        """
        Génère un log unique.
        Distribution : 75% normal, 25% suspect.
        """
        roll = random.random()
        if roll < 0.75:
            return self._normal_traffic()
        else:
            return self._suspicious_traffic()

    def generate_batch(self, n: int = 50) -> list[dict]:
        """
        Génère n logs avec injection aléatoire de scénarios d'attaque.
        """
        logs = []

        # Injecte 1-2 scénarios d'attaque structurés
        num_attacks = random.randint(1, 2)
        for _ in range(num_attacks):
            src = random.choice(EXTERNAL_IPS)
            dst = random.choice(INTERNAL_SUBNET)
            attack_type = random.choice(["brute_force", "port_scan", "exfiltration"])

            if attack_type == "brute_force":
                logs.extend(self.attack.brute_force_ssh(src, dst, count=random.randint(4, 8)))
            elif attack_type == "port_scan":
                logs.extend(self.attack.port_scan(src, dst))
            elif attack_type == "exfiltration":
                logs.extend(self.attack.data_exfiltration(src, dst))

        # Complète avec des logs individuels
        remaining = max(0, n - len(logs))
        for _ in range(remaining):
            logs.append(self.generate())

        random.shuffle(logs)
        return logs[:n]
