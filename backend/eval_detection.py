"""
eval_detection.py — Évaluation précision/rappel du moteur de détection sur un
jeu de logs SIMULÉ ET ÉTIQUETÉ (vérité terrain connue par IP).

Ce n'est PAS une mesure sur du trafic réel : les attaques et le trafic
légitime sont générés ici, avec des cas volontairement difficiles des deux
côtés (attaques sous le seuil des règles ; trafic légitime qui ressemble à
une attaque). Les résultats dépendent de ces choix, visibles dans le code.

Chaque tirage (seed) : 50 IP légitimes + 10 IP attaquantes
(3 brute force SSH, 3 scans de ports, 2 exfiltrations, 2 accès services critiques).

Usage (nécessite POSTGRES_* et une base PostgreSQL joignable) :
    python eval_detection.py [--seeds 30]
"""
import argparse
import random
from datetime import datetime, timedelta

import database
import detector
from detector import DetectionEngine
from ml_detector import MLAnomalyDetector

# Le flux threat intel externe rendrait l'évaluation non déterministe (réseau) :
# la règle "IP Malveillante Connue" est donc exclue de cette évaluation.
detector.get_known_bad_ips = lambda: (set(), "désactivé pour l'évaluation")

RULES = {
    "brute":    "Brute Force SSH",
    "scan":     "Port Scan",
    "exfil":    "Volume Anormal",
    "critical": None,  # 3 règles : Accès Telnet/SMB/RDP Critique
}
N_BENIGN, ATTACKS = 50, {"brute": 3, "scan": 3, "exfil": 2, "critical": 2}


def _ts(rng, minutes_back=30):
    return (datetime.utcnow() - timedelta(seconds=rng.randint(0, minutes_back * 60))).isoformat()


def _log(rng, ip, port, action, nbytes):
    return (_ts(rng), ip, "192.168.1.10", rng.randint(1024, 65535), port,
            "TCP", action, nbytes, "LOW", "eval")


def gen_benign(rng, ip):
    """Trafic légitime, dont des cas qui ressemblent à une attaque."""
    kind = rng.choices(
        ["normal", "typo_ssh", "misconfig", "backup", "legacy_telnet"],
        weights=[70, 10, 5, 10, 5])[0]
    logs = []
    if kind == "normal":
        for _ in range(rng.randint(5, 40)):
            logs.append(_log(rng, ip, rng.choice([80, 443, 53, 8080]), "ALLOW", rng.randint(500, 50_000)))
        for _ in range(rng.randint(0, 3)):
            logs.append(_log(rng, ip, rng.randint(1000, 9000), "DENY", 64))
    elif kind == "typo_ssh":  # utilisateur qui se trompe de mot de passe : 1 à 4 refus
        for _ in range(rng.randint(1, 4)):
            logs.append(_log(rng, ip, 22, "DENY", 128))
        for _ in range(rng.randint(3, 15)):
            logs.append(_log(rng, ip, 443, "ALLOW", rng.randint(500, 50_000)))
    elif kind == "misconfig":  # hôte mal configuré : 8 à 12 ports fermés (ressemble à un scan)
        for port in rng.sample(range(1000, 9000), rng.randint(8, 12)):
            logs.append(_log(rng, ip, port, "DENY", 64))
    elif kind == "backup":  # gros transfert légitime : 1,1 à 3 Mo (ressemble à de l'exfiltration)
        total = rng.randint(1_100_000, 3_000_000)
        n = rng.randint(3, 6)
        for _ in range(n):
            logs.append(_log(rng, ip, 443, "ALLOW", total // n))
    else:  # équipement legacy qui sonde Telnet
        logs.append(_log(rng, ip, 23, "DENY", 64))
        for _ in range(rng.randint(3, 10)):
            logs.append(_log(rng, ip, 443, "ALLOW", rng.randint(500, 20_000)))
    return kind, logs


def gen_attack(rng, ip, kind):
    """Attaques d'intensité variable, certaines SOUS le seuil des règles."""
    logs = []
    if kind == "brute":      # seuil de la règle : 5 tentatives
        for _ in range(rng.randint(3, 12)):
            logs.append(_log(rng, ip, 22, "DENY", 128))
    elif kind == "scan":     # seuil : 8 ports distincts
        for port in rng.sample(range(1, 1024), rng.randint(4, 20)):
            logs.append(_log(rng, ip, port, "DENY", 64))
    elif kind == "exfil":    # seuil : 1 Mo cumulé
        total = rng.randint(400_000, 6_000_000)
        n = rng.randint(3, 6)
        for _ in range(n):
            logs.append(_log(rng, ip, rng.choice([80, 443, 8080]), "ALLOW", total // n))
    else:                    # critical : Telnet/SMB/RDP refusé
        for _ in range(rng.randint(1, 3)):
            logs.append(_log(rng, ip, rng.choice([23, 445, 3389]), "DENY", 64))
    return logs


def build_dataset(rng):
    labels, logs = {}, []   # labels[ip] = "benign:<kind>" ou "attack:<kind>"
    used = set()

    def fresh_ip(prefix):
        while True:
            ip = f"{prefix}.{rng.randint(1, 254)}"
            if ip not in used:
                used.add(ip)
                return ip

    for _ in range(N_BENIGN):
        ip = fresh_ip(rng.choice(["192.168.1", "10.0.0", "172.16.5"]))
        kind, l = gen_benign(rng, ip)
        labels[ip] = f"benign:{kind}"
        logs += l
    for kind, n in ATTACKS.items():
        for _ in range(n):
            ip = fresh_ip(rng.choice(["91.200.12", "185.220.101", "104.28.7"]))
            labels[ip] = f"attack:{kind}"
            logs += gen_attack(rng, ip, kind)
    return labels, logs


def load(logs):
    conn = database.get_db()
    conn.execute("TRUNCATE TABLE logs, alerts RESTART IDENTITY")
    cur = conn.cursor()
    for row in logs:
        cur.execute("""INSERT INTO logs (timestamp, src_ip, dst_ip, src_port, dst_port,
                       protocol, action, bytes, severity, message)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", row)
    conn.commit()
    conn.close()


def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else None
    r = tp / (tp + fn) if tp + fn else None
    return p, r


def run_seed(seed, contaminations):
    rng = random.Random(seed)
    labels, logs = build_dataset(rng)
    load(logs)

    engine = DetectionEngine(window_minutes=60)
    result = engine.run()
    by_rule = {}
    for a in result["alerts"]:
        by_rule.setdefault(a["rule_name"], set()).add(a["src_ip"])
    fired = {k: (set().union(*[v for n, v in by_rule.items()
                               if n.startswith("Accès")]) if k == "critical"
                 else by_rule.get(name, set()))
             for k, name in RULES.items()}
    rules_any = set().union(*fired.values())
    attackers = {ip for ip, l in labels.items() if l.startswith("attack:")}

    out = {"rules": {}, "n_logs": len(logs), "n_ips": len(labels)}
    for k in RULES:
        truth = {ip for ip, l in labels.items() if l == f"attack:{k}"}
        tp, fp, fn = len(fired[k] & truth), len(fired[k] - truth), len(truth - fired[k])
        out["rules"][k] = (tp, fp, fn)
    tp, fp, fn = len(rules_any & attackers), len(rules_any - attackers), len(attackers - rules_any)
    out["rules_any"] = (tp, fp, fn)
    benign = set(labels) - attackers
    out["rules_fpr"] = len(rules_any & benign) / len(benign)

    fpk = {}
    for k in RULES:
        for ip in fired[k] - {i for i, l in labels.items() if l == f"attack:{k}"}:
            kind = labels[ip]
            fpk[(k, kind)] = fpk.get((k, kind), 0) + 1
    out["fp_by_kind"] = fpk
    out["benign_kinds"] = {}
    for l in labels.values():
        out["benign_kinds"][l] = out["benign_kinds"].get(l, 0) + 1
    out["ml"] = {}
    missed_by_rules = attackers - rules_any
    for c in contaminations:
        # les alertes des règles ne perturbent pas le ML (il lit la table logs)
        ml = MLAnomalyDetector(window_minutes=60, contamination=c).run()
        flagged = {a["src_ip"] for a in ml["alerts"]}
        tp, fp, fn = len(flagged & attackers), len(flagged - attackers), len(attackers - flagged)
        out["ml"][c] = {
            "prf": (tp, fp, fn),
            "fpr": len(flagged & benign) / len(benign),
            "missed_by_rules_caught": (len(flagged & missed_by_rules), len(missed_by_rules)),
            "union_tp_fp_fn": (
                len((flagged | rules_any) & attackers),
                len((flagged | rules_any) - attackers),
                len(attackers - (flagged | rules_any))),
        }
    return out


def agg(results, key_fn):
    tp = sum(key_fn(r)[0] for r in results)
    fp = sum(key_fn(r)[1] for r in results)
    fn = sum(key_fn(r)[2] for r in results)
    p, r = prf(tp, fp, fn)
    return tp, fp, fn, p, r


def fmt(x):
    return "n/a" if x is None else f"{x:.1%}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=30)
    args = ap.parse_args()
    database.init_db()
    contaminations = [0.05, 0.1, 0.15, 0.2]

    results = [run_seed(s, contaminations) for s in range(args.seeds)]
    n_logs = sum(r["n_logs"] for r in results)
    n_ips = sum(r["n_ips"] for r in results)
    n_att = args.seeds * sum(ATTACKS.values())
    print(f"\n{args.seeds} tirages | {n_logs} logs | {n_ips} IP dont {n_att} attaquantes "
          f"({n_att / n_ips:.0%}) | agrégé sur l'ensemble des tirages\n")

    print("=== Règles à seuils (IP Malveillante Connue exclue) ===")
    print(f"{'Règle':<22}{'TP':>5}{'FP':>5}{'FN':>5}{'Précision':>11}{'Rappel':>9}")
    for k in RULES:
        tp, fp, fn, p, r = agg(results, lambda x, k=k: x["rules"][k])
        print(f"{k:<22}{tp:>5}{fp:>5}{fn:>5}{fmt(p):>11}{fmt(r):>9}")
    tp, fp, fn, p, r = agg(results, lambda x: x["rules_any"])
    print(f"{'TOUTES (union)':<22}{tp:>5}{fp:>5}{fn:>5}{fmt(p):>11}{fmt(r):>9}")
    fpr = sum(x["rules_fpr"] for x in results) / len(results)
    print(f"Taux de faux positifs (IP légitimes alertées / IP légitimes) : {fpr:.1%}\n")

    kinds, fpk = {}, {}
    for r in results:
        for kd, n in r["benign_kinds"].items():
            kinds[kd] = kinds.get(kd, 0) + n
        for key, n in r["fp_by_kind"].items():
            fpk[key] = fpk.get(key, 0) + n
    print("Origine des faux positifs des règles (règle, type de trafic légitime -> nb IP alertées / nb IP de ce type) :")
    for (rule, kd), n in sorted(fpk.items()):
        print(f"  {rule:<9} <- {kd:<14} {n:>4} / {kinds[kd]}")
    print()

    print("=== Isolation Forest (par IP, toutes attaques confondues) ===")
    print(f"{'contamination':<15}{'TP':>5}{'FP':>5}{'FN':>5}{'Précision':>11}{'Rappel':>9}{'FPR':>8}")
    for c in contaminations:
        tp, fp, fn, p, r = agg(results, lambda x, c=c: x["ml"][c]["prf"])
        f = sum(x["ml"][c]["fpr"] for x in results) / len(results)
        print(f"{c:<15}{tp:>5}{fp:>5}{fn:>5}{fmt(p):>11}{fmt(r):>9}{f:>8.1%}")

    print("\n=== Complémentarité : attaquants ratés par les règles, retrouvés par le ML ===")
    for c in contaminations:
        caught = sum(x["ml"][c]["missed_by_rules_caught"][0] for x in results)
        missed = sum(x["ml"][c]["missed_by_rules_caught"][1] for x in results)
        tp, fp, fn, p, r = agg(results, lambda x, c=c: x["ml"][c]["union_tp_fp_fn"])
        print(f"contamination {c}: {caught}/{missed} retrouvés | règles+ML: "
              f"précision {fmt(p)}, rappel {fmt(r)}")


if __name__ == "__main__":
    main()
