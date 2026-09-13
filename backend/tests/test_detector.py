"""
test_detector.py — Couvre les 5 règles de détection de detector.py.
Chaque règle a un cas positif (déclenche une alerte) et un cas négatif
(ne déclenche rien). Utilise une DB SQLite temporaire (voir conftest.py).
"""
from datetime import datetime, timedelta


def insert_log(database, **overrides):
    """Insère un log directement en DB de test avec des valeurs par défaut."""
    log = {
        "timestamp": datetime.utcnow().isoformat(),
        "src_ip": "1.2.3.4",
        "dst_ip": "192.168.1.10",
        "src_port": 55000,
        "dst_port": 80,
        "protocol": "TCP",
        "action": "ALLOW",
        "bytes": 100,
        "severity": "LOW",
        "message": "test",
    }
    log.update(overrides)
    conn = database.get_db()
    conn.execute(
        """INSERT INTO logs (timestamp, src_ip, dst_ip, src_port, dst_port,
                              protocol, action, bytes, severity, message)
           VALUES (%(timestamp)s, %(src_ip)s, %(dst_ip)s, %(src_port)s, %(dst_port)s,
                   %(protocol)s, %(action)s, %(bytes)s, %(severity)s, %(message)s)""",
        log,
    )
    conn.commit()
    conn.close()


# ── Règle 1 : Brute Force SSH ──────────────────────────────────────────────────
def test_brute_force_ssh_detected(app_context):
    import database, detector
    for _ in range(5):
        insert_log(database, src_ip="9.9.9.9", dst_port=22, action="DENY")
    engine = detector.DetectionEngine(window_minutes=60)
    alerts = engine.rule_brute_force_ssh()
    assert len(alerts) == 1
    assert alerts[0].rule_name == "Brute Force SSH"
    assert alerts[0].src_ip == "9.9.9.9"
    assert alerts[0].mitre["technique_id"] == "T1110"


def test_brute_force_ssh_not_detected_below_threshold(app_context):
    import database, detector
    for _ in range(4):
        insert_log(database, src_ip="9.9.9.9", dst_port=22, action="DENY")
    engine = detector.DetectionEngine(window_minutes=60)
    assert engine.rule_brute_force_ssh() == []


# ── Règle 2 : Port Scan ────────────────────────────────────────────────────────
def test_port_scan_detected(app_context):
    import database, detector
    for port in range(1, 9):
        insert_log(database, src_ip="8.8.4.4", dst_port=port, action="DENY")
    engine = detector.DetectionEngine(window_minutes=60)
    alerts = engine.rule_port_scan()
    assert len(alerts) == 1
    assert alerts[0].rule_name == "Port Scan"


def test_port_scan_not_detected_below_threshold(app_context):
    import database, detector
    for port in range(1, 5):
        insert_log(database, src_ip="8.8.4.4", dst_port=port, action="DENY")
    engine = detector.DetectionEngine(window_minutes=60)
    assert engine.rule_port_scan() == []


# ── Règle 3 : Volumétrie anormale ──────────────────────────────────────────────
def test_data_exfiltration_detected(app_context):
    import database, detector
    insert_log(database, src_ip="7.7.7.7", action="ALLOW", bytes=2_000_000)
    engine = detector.DetectionEngine(window_minutes=60)
    alerts = engine.rule_data_exfiltration()
    assert len(alerts) == 1
    assert alerts[0].rule_name == "Volume Anormal"


def test_data_exfiltration_not_detected_below_threshold(app_context):
    import database, detector
    insert_log(database, src_ip="7.7.7.7", action="ALLOW", bytes=500_000)
    engine = detector.DetectionEngine(window_minutes=60)
    assert engine.rule_data_exfiltration() == []


# ── Règle 4 : Accès service critique ───────────────────────────────────────────
def test_critical_service_detected(app_context):
    import database, detector
    insert_log(database, src_ip="6.6.6.6", dst_port=3389, action="DENY")
    engine = detector.DetectionEngine(window_minutes=60)
    alerts = engine.rule_critical_service()
    assert len(alerts) == 1
    assert "RDP" in alerts[0].rule_name


def test_critical_service_not_detected_on_allow(app_context):
    import database, detector
    insert_log(database, src_ip="6.6.6.6", dst_port=3389, action="ALLOW")
    engine = detector.DetectionEngine(window_minutes=60)
    assert engine.rule_critical_service() == []


# ── Règle 5 : IP malveillante connue ───────────────────────────────────────────
def test_known_bad_ip_detected(app_context):
    import database, detector
    from config import KNOWN_BAD_IPS
    bad_ip = next(iter(KNOWN_BAD_IPS))
    insert_log(database, src_ip=bad_ip)
    engine = detector.DetectionEngine(window_minutes=60)
    alerts = engine.rule_known_bad_ip()
    assert len(alerts) == 1
    assert alerts[0].src_ip == bad_ip


def test_known_bad_ip_not_detected_when_absent(app_context):
    import detector
    engine = detector.DetectionEngine(window_minutes=60)
    assert engine.rule_known_bad_ip() == []
