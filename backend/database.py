"""
database.py — Connexion PostgreSQL et initialisation du schéma.

Le reste du code applicatif (routes/*.py, detector.py) a été écrit contre
l'API sqlite3 : placeholders "?", `conn.execute(...)` directement sur la
connexion, `cursor.lastrowid` après un INSERT. Plutôt que réécrire chaque
site d'appel (~40, à travers 5 fichiers) pour l'API psycopg2 (placeholders
"%s", exécution uniquement via un curseur, pas de lastrowid), ce module
fournit un fin adaptateur qui traduit ces appels vers psycopg2 : la moitié la
plus mécanique de la migration SQLite -> PostgreSQL sans toucher à la logique
métier. Un ORM (SQLAlchemy) serait le choix standard pour un projet plus
large ; ici la surface SQL est petite et déjà entièrement paramétrée, donc
l'adaptateur reste simple et sans risque d'injection.
"""
import psycopg2
import psycopg2.errors
import psycopg2.extras

from config import (
    POSTGRES_HOST, POSTGRES_PORT, POSTGRES_DB, POSTGRES_USER, POSTGRES_PASSWORD,
)


class _Cursor:
    """Enveloppe un curseur psycopg2 : traduit les "?" en "%s", et émule
    `lastrowid` (absent de psycopg2) en ajoutant RETURNING id aux INSERT."""

    def __init__(self, raw_cursor):
        self._cursor = raw_cursor
        self.lastrowid = None

    def execute(self, sql, params=()):
        sql = sql.replace("?", "%s")
        stripped = sql.strip().upper()
        if stripped.startswith("INSERT") and "RETURNING" not in stripped:
            sql += " RETURNING id"
            self._cursor.execute(sql, params)
            self.lastrowid = self._cursor.fetchone()["id"]
        else:
            self._cursor.execute(sql, params)
        return self

    def fetchone(self):
        row = self._cursor.fetchone()
        return _Row(row) if row is not None else None

    def fetchall(self):
        return [_Row(row) for row in self._cursor.fetchall()]


class _Row(dict):
    """Autorise à la fois l'accès par nom (comme sqlite3.Row/dict(row)) et
    par index [0] (utilisé par endroits pour un COUNT(*) sans alias)."""

    def __init__(self, row):
        super().__init__(row)
        self._values = list(row.values())

    def __getitem__(self, key):
        if isinstance(key, int):
            return self._values[key]
        return super().__getitem__(key)


class _Connection:
    """Enveloppe une connexion psycopg2 pour exposer `.execute()` directement
    dessus, comme le permet sqlite3.Connection."""

    def __init__(self, raw_conn):
        self._conn = raw_conn

    def execute(self, sql, params=()):
        return self.cursor().execute(sql, params)

    def cursor(self):
        return _Cursor(self._conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor))

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()


def get_db() -> _Connection:
    """Retourne une connexion PostgreSQL (enveloppée, voir _Connection)."""
    raw = psycopg2.connect(
        host=POSTGRES_HOST,
        port=POSTGRES_PORT,
        dbname=POSTGRES_DB,
        user=POSTGRES_USER,
        password=POSTGRES_PASSWORD,
    )
    return _Connection(raw)


def init_db():
    """
    Crée les tables si elles n'existent pas.

    Appelé une seule fois par processus grâce à `gunicorn --preload` (voir
    Dockerfile) — sans ça, chaque worker importerait app.py et appellerait
    init_db() indépendamment, avec un risque de course sur le "CREATE TABLE
    IF NOT EXISTS" (PostgreSQL, contrairement à SQLite, n'en fait pas une
    opération atomique sous concurrence : psycopg2.errors.DuplicateTable a
    été observé en pratique avec 4 workers non préchargés). Le try/except
    ci-dessous reste une seconde ligne de défense pour un futur scénario
    multi-pods (actuellement replicas=1 partout).
    """
    conn = get_db()
    cursor = conn.cursor()

    try:
        # Table principale : chaque ligne = un événement réseau
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id          SERIAL PRIMARY KEY,
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
                id          SERIAL PRIMARY KEY,
                timestamp   TEXT    NOT NULL,
                rule_name   TEXT    NOT NULL,           -- Ex: "Brute Force Detected"
                src_ip      TEXT,
                severity    TEXT    NOT NULL,
                description TEXT,
                resolved    INTEGER DEFAULT 0           -- 0 = ouvert, 1 = résolu
            )
        """)
        conn.commit()
    except psycopg2.errors.DuplicateTable:
        conn.rollback()

    conn.close()
    print(f"[DB] Base de données initialisée -> postgresql://{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}")
