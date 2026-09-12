"""
detector.py — Moteur de détection d'anomalies pour le Mini-SIEM (Jour 7)

Règles implémentées :
    1. Brute Force SSH   : >= 5 tentatives SSH DENY depuis la même IP en 1 min
    2. Port Scan         : >= 8 ports distincts ciblés depuis la même IP en 2 min
    3. Volumétrie anormale : flux ALLOW > 1 MB depuis une IP interne
    4. Accès service critique DENY depuis IP externe (RDP, SMB, Telnet)
    5. IP connue malveillante

Usage :
    from detector import DetectionEngine
    engine = DetectionEngine()
    alerts = engine.run()   # analyse la DB et retourne les alertes générées
"""
import sqlite3
from datetime import datetime, timedelta
from dataclasses import dataclass, field

from config import (
    DB_PATH,
    KNOWN_BAD_IPS,
    CRITICAL_PORTS,
    HIGH_PORTS,
    CRITICAL_SERVICE_NAMES,
    MITRE_MAPPING,
)


@dataclass
class Alert:
    rule_name:   str
    src_ip:      str
    severity:    str
    description: str
    timestamp:   str
    mitre:       dict = field(default_factory=dict)


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


class DetectionEngine:
    """
    Analyse les logs récents et génère des alertes selon des règles prédéfinies.
    """

    def __init__(self, window_minutes: int = 5):
        self.window = window_minutes
        self.since  = (datetime.utcnow() - timedelta(minutes=window_minutes)).isoformat()

    def _fetch(self, query: str, params: tuple = ()) -> list:
        conn = get_db()
        rows = conn.execute(query, params).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def _alert_exists(self, rule_name: str, src_ip: str, since_minutes: int = 10) -> bool:
        """Évite de créer des doublons d'alertes récentes."""
        since = (datetime.utcnow() - timedelta(minutes=since_minutes)).isoformat()
        conn  = get_db()
        count = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE rule_name=? AND src_ip=? AND timestamp>=?",
            (rule_name, src_ip, since)
        ).fetchone()[0]
        conn.close()
        return count > 0

    # ── Règle 1 : Brute Force SSH ─────────────────────────────────────────────
    def rule_brute_force_ssh(self) -> list[Alert]:
        rows = self._fetch("""
            SELECT src_ip, COUNT(*) as cnt
            FROM logs
            WHERE dst_port = 22
              AND action   = 'DENY'
              AND timestamp >= ?
            GROUP BY src_ip
            HAVING cnt >= 5
        """, (self.since,))

        alerts = []
        for r in rows:
            ip = r["src_ip"]
            if self._alert_exists("Brute Force SSH", ip):
                continue
            alerts.append(Alert(
                rule_name   = "Brute Force SSH",
                src_ip      = ip,
                severity    = "CRITICAL",
                description = f"Brute force SSH détecté : {r['cnt']} tentatives en {self.window} min depuis {ip}",
                timestamp   = datetime.utcnow().isoformat(),
                mitre       = MITRE_MAPPING.get("Brute Force SSH", {}),
            ))
        return alerts

    # ── Règle 2 : Port Scan ───────────────────────────────────────────────────
    def rule_port_scan(self) -> list[Alert]:
        rows = self._fetch("""
            SELECT src_ip, COUNT(DISTINCT dst_port) as ports, COUNT(*) as cnt
            FROM logs
            WHERE action    = 'DENY'
              AND timestamp >= ?
            GROUP BY src_ip
            HAVING ports >= 8
        """, (self.since,))

        alerts = []
        for r in rows:
            ip = r["src_ip"]
            if self._alert_exists("Port Scan", ip):
                continue
            alerts.append(Alert(
                rule_name   = "Port Scan",
                src_ip      = ip,
                severity    = "HIGH",
                description = f"Port scan détecté : {r['ports']} ports distincts ciblés en {self.window} min depuis {ip}",
                timestamp   = datetime.utcnow().isoformat(),
                mitre       = MITRE_MAPPING.get("Port Scan", {}),
            ))
        return alerts

    # ── Règle 3 : Volumétrie anormale ─────────────────────────────────────────
    def rule_data_exfiltration(self) -> list[Alert]:
        rows = self._fetch("""
            SELECT src_ip, SUM(bytes) as total_bytes
            FROM logs
            WHERE action    = 'ALLOW'
              AND timestamp >= ?
            GROUP BY src_ip
            HAVING total_bytes > 1000000
        """, (self.since,))

        alerts = []
        for r in rows:
            ip    = r["src_ip"]
            mb    = r["total_bytes"] / 1_000_000
            if self._alert_exists("Volume Anormal", ip):
                continue
            alerts.append(Alert(
                rule_name   = "Volume Anormal",
                src_ip      = ip,
                severity    = "HIGH",
                description = f"Volume de données anormal : {mb:.1f} MB depuis {ip} en {self.window} min",
                timestamp   = datetime.utcnow().isoformat(),
                mitre       = MITRE_MAPPING.get("Volume Anormal", {}),
            ))
        return alerts

    # ── Règle 4 : Accès service critique ──────────────────────────────────────
    def rule_critical_service(self) -> list[Alert]:
        rows = self._fetch("""
            SELECT src_ip, dst_port, COUNT(*) as cnt
            FROM logs
            WHERE action    = 'DENY'
              AND dst_port  IN (23, 445, 3389)
              AND timestamp >= ?
            GROUP BY src_ip, dst_port
        """, (self.since,))

        alerts = []
        for r in rows:
            ip      = r["src_ip"]
            service = CRITICAL_SERVICE_NAMES.get(r["dst_port"], str(r["dst_port"]))
            rule    = f"Accès {service} Critique"
            if self._alert_exists(rule, ip):
                continue
            alerts.append(Alert(
                rule_name   = rule,
                src_ip      = ip,
                severity    = "CRITICAL",
                description = f"Tentative d'accès {service} (port {r['dst_port']}) bloquée depuis {ip} — {r['cnt']} fois",
                timestamp   = datetime.utcnow().isoformat(),
                mitre       = MITRE_MAPPING.get(rule, {}),
            ))
        return alerts

    # ── Règle 5 : IP malveillante connue ──────────────────────────────────────
    def rule_known_bad_ip(self) -> list[Alert]:
        alerts = []
        for ip in KNOWN_BAD_IPS:
            rows = self._fetch("""
                SELECT COUNT(*) as cnt FROM logs
                WHERE src_ip = ? AND timestamp >= ?
            """, (ip, self.since))
            cnt = rows[0]["cnt"] if rows else 0
            if cnt == 0:
                continue
            if self._alert_exists("IP Malveillante Connue", ip):
                continue
            alerts.append(Alert(
                rule_name   = "IP Malveillante Connue",
                src_ip      = ip,
                severity    = "HIGH",
                description = f"Activité détectée depuis IP malveillante connue {ip} — {cnt} événements",
                timestamp   = datetime.utcnow().isoformat(),
                mitre       = MITRE_MAPPING.get("IP Malveillante Connue", {}),
            ))
        return alerts

    # ── Calcul du score de risque global ──────────────────────────────────────
    def compute_risk_score(self) -> dict:
        """
        Score de 0 à 100 basé sur la distribution des sévérités récentes.
        """
        rows = self._fetch("""
            SELECT severity, COUNT(*) as cnt
            FROM logs
            WHERE timestamp >= ?
            GROUP BY severity
        """, (self.since,))

        weights = {"LOW": 1, "MEDIUM": 3, "HIGH": 10, "CRITICAL": 25}
        total_weighted = 0
        total_events   = 0

        for r in rows:
            w               = weights.get(r["severity"], 1)
            total_weighted += w * r["cnt"]
            total_events   += r["cnt"]

        if total_events == 0:
            return {"score": 0, "level": "NORMAL", "events": 0}

        raw_score = total_weighted / total_events
        score     = min(100, int(raw_score * 4))

        if score >= 75:   level = "CRITIQUE"
        elif score >= 50: level = "ELEVE"
        elif score >= 25: level = "MOYEN"
        else:             level = "NORMAL"

        return {"score": score, "level": level, "events": total_events}

    # ── Point d'entrée principal ───────────────────────────────────────────────
    def run(self) -> dict:
        """
        Lance toutes les règles et sauvegarde les alertes en base.
        Retourne un résumé.
        """
        all_alerts = (
            self.rule_brute_force_ssh()   +
            self.rule_port_scan()         +
            self.rule_data_exfiltration() +
            self.rule_critical_service()  +
            self.rule_known_bad_ip()
        )

        # Sauvegarde en DB
        if all_alerts:
            conn   = get_db()
            cursor = conn.cursor()
            for a in all_alerts:
                cursor.execute("""
                    INSERT INTO alerts (timestamp, rule_name, src_ip, severity, description, resolved)
                    VALUES (?, ?, ?, ?, ?, 0)
                """, (a.timestamp, a.rule_name, a.src_ip, a.severity, a.description))
            conn.commit()
            conn.close()

        risk = self.compute_risk_score()

        return {
            "alerts_generated": len(all_alerts),
            "alerts":           [vars(a) for a in all_alerts],
            "risk_score":       risk,
        }


# ── Script standalone ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    engine = DetectionEngine(window_minutes=60)
    result = engine.run()

    print(f"\n{'='*55}")
    print(f"  Résultat de la détection")
    print(f"{'='*55}")
    print(f"  Alertes générées : {result['alerts_generated']}")
    print(f"  Score de risque  : {result['risk_score']['score']}/100 ({result['risk_score']['level']})")
    print(f"  Événements analysés : {result['risk_score']['events']}")

    if result["alerts"]:
        print(f"\n  Alertes :")
        for a in result["alerts"]:
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(a["severity"], "⚪")
            print(f"  {icon} [{a['severity']}] {a['rule_name']} — {a['src_ip']}")
            print(f"       {a['description']}")
    else:
        print("\n  Aucune nouvelle alerte détectée.")
    print(f"{'='*55}\n")
