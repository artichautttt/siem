import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "siem.db")


def get_db():
    """Retourne une connexion SQLite avec Row factory (accès par nom de colonne)."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Crée les tables si elles n'existent pas."""
    conn = get_db()
    cursor = conn.cursor()

    # Table principale : chaque ligne = un événement réseau
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,          -- ISO 8601 ex: 2025-04-23T14:32:01
            src_ip      TEXT    NOT NULL,           -- IP source
            dst_ip      TEXT    NOT NULL,           -- IP destination
            src_port    INTEGER,                    -- Port source
            dst_port    INTEGER NOT NULL,           -- Port destination
            protocol    TEXT    NOT NULL,           -- TCP / UDP / ICMP
            action      TEXT    NOT NULL,           -- ALLOW / DENY
            bytes       INTEGER DEFAULT 0,          -- Volume de données (octets)
            severity    TEXT    DEFAULT 'LOW',      -- LOW / MEDIUM / HIGH / CRITICAL
            message     TEXT                        -- Description libre
        )
    """)

    # Table des alertes générées par le moteur de détection (Jour 7)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            rule_name   TEXT    NOT NULL,           -- Ex: "Brute Force Detected"
            src_ip      TEXT,
            severity    TEXT    NOT NULL,
            description TEXT,
            resolved    INTEGER DEFAULT 0           -- 0 = ouvert, 1 = résolu
        )
    """)

    conn.commit()
    conn.close()
    print("[DB] Base de données initialisée → siem.db")
