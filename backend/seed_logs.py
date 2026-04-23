"""
seed_logs.py — Générateur de faux logs réseau pour tester le SIEM.
Lance ce script pendant que le serveur Flask tourne.

Usage :
    python seed_logs.py            # génère 50 logs aléatoires
    python seed_logs.py --n 200    # génère 200 logs
"""
import requests
import random
import argparse
from datetime import datetime, timedelta

API_URL = "http://localhost:5000/api/logs"

# Données de simulation réalistes
INTERNAL_IPS  = [f"192.168.1.{i}" for i in range(1, 20)]
EXTERNAL_IPS  = ["45.33.32.156", "198.51.100.5", "203.0.113.42",
                 "10.0.0.1", "172.16.0.55", "8.8.8.8", "1.1.1.1"]
PROTOCOLS     = ["TCP", "TCP", "TCP", "UDP", "ICMP"]  # TCP plus fréquent
COMMON_PORTS  = [22, 80, 443, 3306, 5432, 8080, 21, 25, 53, 3389]

SCENARIOS = [
    # (dst_port, action, severity, message)
    (22,   "DENY",  "HIGH",     "Tentative de connexion SSH refusée"),
    (22,   "DENY",  "CRITICAL", "Brute force SSH détecté — 10 tentatives en 1 min"),
    (80,   "ALLOW", "LOW",      "Requête HTTP normale"),
    (443,  "ALLOW", "LOW",      "Requête HTTPS normale"),
    (3306, "DENY",  "HIGH",     "Accès MySQL bloqué depuis IP externe"),
    (3389, "DENY",  "HIGH",     "Tentative RDP bloquée"),
    (21,   "DENY",  "MEDIUM",   "Tentative FTP non autorisée"),
    (8080, "ALLOW", "LOW",      "Trafic API interne"),
    (53,   "ALLOW", "LOW",      "Requête DNS normale"),
    (25,   "DENY",  "MEDIUM",   "Tentative SMTP suspecte"),
]


def random_timestamp(minutes_back=60):
    delta = timedelta(minutes=random.randint(0, minutes_back))
    return (datetime.utcnow() - delta).isoformat()


def generate_log():
    src_ip = random.choice(INTERNAL_IPS + EXTERNAL_IPS)
    dst_ip = random.choice(INTERNAL_IPS)
    dst_port, action, severity, message = random.choice(SCENARIOS)

    return {
        "src_ip":   src_ip,
        "dst_ip":   dst_ip,
        "src_port": random.randint(1024, 65535),
        "dst_port": dst_port,
        "protocol": random.choice(PROTOCOLS),
        "action":   action,
        "bytes":    random.randint(64, 65000),
        "severity": severity,
        "message":  message,
        "timestamp": random_timestamp(),
    }


def main(n: int):
    print(f"[seed] Génération de {n} logs → {API_URL}")
    success = 0
    for i in range(n):
        payload = generate_log()
        try:
            r = requests.post(API_URL, json=payload, timeout=3)
            if r.status_code == 201:
                success += 1
            else:
                print(f"  [!] Erreur log {i+1} : {r.status_code} {r.text}")
        except requests.ConnectionError:
            print("[ERREUR] Impossible de joindre le serveur Flask.")
            print("         Lance d'abord : python app.py")
            break

    print(f"[seed] {success}/{n} logs insérés avec succès.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--n", type=int, default=50, help="Nombre de logs à générer")
    args = parser.parse_args()
    main(args.n)
