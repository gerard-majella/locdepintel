"""SQLite storage with versioned, append-only schema migrations."""

import sqlite3
import threading
from contextlib import contextmanager

from . import settings


def db_path():
    return settings.home_data() / "locdepintel.sqlite3"


# Numbered, append-only schema migrations. Never edit a released step: add a new one.
# Step 1 is the DepWatch 0.7 schema written with IF NOT EXISTS, so old databases
# (user_version 0) pass through it without losing data.
MIGRATIONS = [
    (
        1,
        """
        CREATE TABLE IF NOT EXISTS scans(
            id INTEGER PRIMARY KEY, started TEXT, ended TEXT, status TEXT, error TEXT,
            packages INTEGER DEFAULT 0, checked INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS inventory(
            env TEXT NOT NULL, ecosystem TEXT NOT NULL, name TEXT NOT NULL,
            version TEXT NOT NULL, direct TEXT, discovered TEXT NOT NULL, seen TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1, PRIMARY KEY(env,ecosystem,name,version));
        CREATE INDEX IF NOT EXISTS idx_inv_active ON inventory(active,ecosystem,name,version);
        CREATE TABLE IF NOT EXISTS events(
            id INTEGER PRIMARY KEY, occurred TEXT, kind TEXT, env TEXT, ecosystem TEXT,
            name TEXT, version TEXT, description TEXT);
        CREATE TABLE IF NOT EXISTS findings(
            id INTEGER PRIMARY KEY, env TEXT, ecosystem TEXT, name TEXT, version TEXT,
            advisory TEXT, kind TEXT, summary TEXT, url TEXT, first_seen TEXT, last_seen TEXT,
            active INTEGER DEFAULT 1, UNIQUE(env,ecosystem,name,version,advisory));
        CREATE TABLE IF NOT EXISTS checks(
            id INTEGER PRIMARY KEY, timestamp TEXT, state TEXT, note TEXT, packages INTEGER);
        CREATE TABLE IF NOT EXISTS envs(
            path TEXT PRIMARY KEY, ecosystem TEXT, last_seen TEXT, state TEXT,
            package_count INTEGER);
        CREATE TABLE IF NOT EXISTS registry_cache(
            ecosystem TEXT, name TEXT, fetched TEXT, payload TEXT,
            PRIMARY KEY(ecosystem,name));
        CREATE TABLE IF NOT EXISTS pulse_advisories(
            id TEXT PRIMARY KEY, kind TEXT, severity TEXT, summary TEXT, url TEXT,
            published TEXT, updated TEXT, fetched TEXT, affected_json TEXT);
        CREATE TABLE IF NOT EXISTS pulse_sync(
            id INTEGER PRIMARY KEY, timestamp TEXT, state TEXT, count INTEGER, note TEXT);
        """,
    ),
    (
        2,
        """
        CREATE TABLE advisory_cache(id TEXT PRIMARY KEY, fetched TEXT NOT NULL, payload TEXT);
        CREATE INDEX idx_findings_active ON findings(active, kind);
        CREATE INDEX idx_events_kind ON events(kind, id);
        """,
    ),
]


SCHEMA_VERSION = MIGRATIONS[-1][0]


_MIGRATED = set()


_MIGRATE_LOCK = threading.Lock()


def _statements(script):
    buffer = ""
    for line in script.splitlines(keepends=True):
        buffer += line
        if sqlite3.complete_statement(buffer):
            if buffer.strip():
                yield buffer
            buffer = ""
    if buffer.strip():
        yield buffer


def _migrate(path):
    """Bring the database at ``path`` up to SCHEMA_VERSION, one atomic step at a time."""
    conn = sqlite3.connect(path, timeout=20, isolation_level=None)  # manual transactions
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        for version, script in MIGRATIONS:
            conn.execute("BEGIN IMMEDIATE")  # take the write lock, then re-check
            try:
                current = conn.execute("PRAGMA user_version").fetchone()[0]
                if current > SCHEMA_VERSION:
                    raise RuntimeError(
                        f"This database was created by a newer version of LocDepIntel "
                        f"(schema {current}, this release supports {SCHEMA_VERSION}). "
                        "Upgrade LocDepIntel."
                    )
                if version > current:
                    for statement in _statements(script):
                        conn.execute(statement)
                    conn.execute(f"PRAGMA user_version={int(version)}")
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
    finally:
        conn.close()


@contextmanager
def db():
    path = str(db_path())
    if path not in _MIGRATED:
        with _MIGRATE_LOCK:
            if path not in _MIGRATED:
                _migrate(path)
                _MIGRATED.add(path)
    conn = sqlite3.connect(path, timeout=20, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=10000")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()
