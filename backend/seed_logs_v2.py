"""
seed_logs_v2.py — Générateur amélioré utilisant LogGenerator + LogParser.
Remplace seed_logs.py du Jour 1.

Usage :
    python seed_logs_v2.py          # 100 logs réalistes
    python seed_logs_v2.py --n 200  # 200 logs
    python seed_logs_v2.py --local  # sans API, directement en DB
"""
import requests
import argparse
import sqlite3
from generator import LogGenerator
from parser import LogParser
from config import DB_PATH, API_KEY

API_URL = "http://localhost:5000/api/logs"


def seed_via_api(n: int):
    """Insère les logs via l'API Flask (serveur doit tourner)."""
    gen    = LogGenerator()
    parser = LogParser()
    logs   = gen.generate_batch(n)

    print(f"[seed] Envoi de {len(logs)} logs vers {API_URL}")
    success = errors = 0
    headers = {"X-API-Key": API_KEY}

    for log in logs:
        parsed, ok, err = parser.parse(log)
        if not ok:
            errors += 1
            continue

        # Retire les champs enrichis que l'API ne connaît pas encore
        payload = {k: v for k, v in parsed.items()
                   if k in ["timestamp", "src_ip", "dst_ip", "src_port",
                             "dst_port", "protocol", "action", "bytes",
                             "severity", "message"]}
        try:
            r = requests.post(API_URL, json=payload, headers=headers, timeout=3)
            if r.status_code == 201:
                success += 1
            else:
                errors += 1
        except requests.ConnectionError:
            print("[ERREUR] Serveur Flask inaccessible. Lance : python app.py")
            return

    print(f"[seed] ✅ {success} logs insérés | ❌ {errors} erreurs")


def seed_direct_db(n: int):
    """Insère les logs directement en SQLite (sans API)."""
    gen    = LogGenerator()
    parser = LogParser()
    logs   = gen.generate_batch(n)

    conn   = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    success = errors = 0

    for log in logs:
        parsed, ok, err = parser.parse(log)
        if not ok:
            errors += 1
            continue
        try:
            cursor.execute("""
                INSERT INTO logs (timestamp, src_ip, dst_ip, src_port, dst_port,
                                  protocol, action, bytes, severity, message)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                parsed["timestamp"], parsed["src_ip"], parsed["dst_ip"],
                parsed.get("src_port"), parsed["dst_port"], parsed["protocol"],
                parsed["action"], parsed["bytes"], parsed["severity"],
                parsed["message"],
            ))
            success += 1
        except Exception as e:
            errors += 1

    conn.commit()
    conn.close()
    print(f"[seed] ✅ {success} logs insérés directement en DB | ❌ {errors} erreurs")


def print_sample(n: int = 5):
    """Affiche des exemples de logs générés pour vérification."""
    gen    = LogGenerator()
    parser = LogParser()
    print(f"\n{'─'*60}")
    print(f"  Exemples de logs générés ({n} logs)")
    print(f"{'─'*60}")
    for log in gen.generate_batch(n):
        parsed, ok, err = parser.parse(log)
        if ok:
            action_icon = "✅" if parsed["action"] == "ALLOW" else "🚫"
            sev_icon = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}.get(parsed["severity"], "⚪")
            print(f"{action_icon} {sev_icon} [{parsed['severity']:<8}] "
                  f"{parsed['src_ip']:<16} → {parsed['dst_ip']:<16} "
                  f":{parsed['dst_port']:<5} {parsed['protocol']:<4} "
                  f"| {parsed['message'][:50]}")
    print(f"{'─'*60}\n")


if __name__ == "__main__":
    parser_arg = argparse.ArgumentParser()
    parser_arg.add_argument("--n",     type=int,  default=100, help="Nombre de logs")
    parser_arg.add_argument("--local", action="store_true",   help="Insertion directe en DB")
    args = parser_arg.parse_args()

    print_sample(5)

    if args.local:
        seed_direct_db(args.n)
    else:
        seed_via_api(args.n)
