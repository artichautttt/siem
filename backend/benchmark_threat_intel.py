"""
benchmark_threat_intel.py — Compare l'ancienne implémentation de la règle
"IP Malveillante Connue" (boucle sur chaque IP de la liste, une requête DB
par IP) avec la nouvelle (une requête groupée + lookup O(1) dans un set),
sur le vrai flux de threat intel externe (~28 000 IP).

Usage : python benchmark_threat_intel.py
Nécessite POSTGRES_* dans l'environnement et une table `logs` avec des
données (peu importe le contenu réel, seul le nombre de lignes influe sur
l'ancienne approche).
"""
import time

from database import get_db
from threat_intel import get_known_bad_ips


def old_approach(bad_ips, since):
    """Reproduit l'implémentation initiale : une requête SQL par IP de la
    liste de threat intel (boucle sur ~28 000 IP)."""
    conn = get_db()
    hits = 0
    for ip in bad_ips:
        row = conn.execute(
            "SELECT COUNT(*) as cnt FROM logs WHERE src_ip = ? AND timestamp >= ?",
            (ip, since),
        ).fetchone()
        if row["cnt"] > 0:
            hits += 1
    conn.close()
    return hits


def new_approach(bad_ips, since):
    """Implémentation actuelle : une requête groupée sur les logs, puis
    test d'appartenance O(1) par IP source observée."""
    conn = get_db()
    rows = conn.execute(
        "SELECT src_ip, COUNT(*) as cnt FROM logs WHERE timestamp >= ? GROUP BY src_ip",
        (since,),
    ).fetchall()
    conn.close()
    return sum(1 for r in rows if r["src_ip"] in bad_ips)


if __name__ == "__main__":
    bad_ips, source = get_known_bad_ips()
    print(f"Threat intel : {len(bad_ips)} IP (source : {source})")

    since = "2020-01-01T00:00:00"  # fenêtre large : couvre tous les logs de test

    conn = get_db()
    total_logs = conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
    conn.close()
    print(f"Logs en base : {total_logs}")

    t0 = time.perf_counter()
    hits_old = old_approach(bad_ips, since)
    t_old = time.perf_counter() - t0
    print(f"Ancienne approche (boucle sur {len(bad_ips)} IP, 1 requête/IP) : {t_old:.3f}s -> {hits_old} correspondance(s)")

    t0 = time.perf_counter()
    hits_new = new_approach(bad_ips, since)
    t_new = time.perf_counter() - t0
    print(f"Nouvelle approche (1 requête groupée + lookup O(1))         : {t_new:.3f}s -> {hits_new} correspondance(s)")

    print(f"\nFacteur d'accélération : {t_old / t_new:.0f}x")
    assert hits_old == hits_new, "Les deux approches doivent trouver les mêmes correspondances !"
