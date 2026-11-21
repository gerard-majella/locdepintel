"""Read-only inventory and OSV monitoring. Only package metadata is read; project code is never imported."""

import json
import os
import pathlib
import re
import sqlite3
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from . import __version__, parsers
from .parsers import npm_lock, python_env  # noqa: F401  (public API)

APP = "LocDepIntel"
USER_AGENT = f"LocDepIntel/{__version__} (+https://github.com/gerard-majella/locdepintel)"


def timestamp():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def home_data():
    if sys.platform == "darwin":
        base = pathlib.Path.home() / "Library" / "Application Support"
    elif sys.platform == "win32":
        base = pathlib.Path(os.getenv("LOCALAPPDATA", pathlib.Path.home()))
    else:
        base = pathlib.Path(os.getenv("XDG_DATA_HOME", pathlib.Path.home() / ".local" / "share"))
    d = base / APP
    d.mkdir(parents=True, exist_ok=True)
    return d


def config_path():
    return home_data() / "config.json"


def suggested_roots():
    """Only user-owned conventional directories; explicit consent is needed before scanning."""
    home = pathlib.Path.home()
    names = ("Documents", "Desktop", "Developer", "Projects", "Code", "src", "Downloads")
    return [
        {
            "name": name,
            "path": str(home / name),
            "exists": (home / name).is_dir(),
            "default": name in ("Documents", "Desktop", "Developer", "Projects", "Code", "src"),
        }
        for name in names
    ]


def load_config():
    try:
        config = json.loads(config_path().read_text())
        if isinstance(config, dict):
            return config
    except (FileNotFoundError, ValueError):
        pass
    return {
        "roots": [str(pathlib.Path.home() / "Documents")],
        "max_depth": 7,
        "max_dirs": 30000,
        "include_global": False,
    }


def setup_status():
    config = load_config()
    with db() as con:
        scans = con.execute(
            "SELECT COUNT(*) FROM scans WHERE status IN ('ok','partial')"
        ).fetchone()[0]
        entries = con.execute("SELECT COUNT(*) FROM inventory").fetchone()[0]
    # Existing users never get forced through a welcome modal.
    completed = bool(config.get("onboarding_complete")) or scans > 0 or entries > 0
    return {
        "complete": completed,
        "existing_user": scans > 0 or entries > 0,
        "suggested_roots": suggested_roots(),
        "roots": config.get("roots", []),
    }


def finish_onboarding(roots=None, skip=False):
    config = load_config()
    if roots is not None:
        config["roots"] = [str(pathlib.Path(p).expanduser().resolve()) for p in roots]
    config["onboarding_complete"] = True
    config["onboarding_skipped"] = bool(skip)
    save_config(config)
    return setup_status()


def save_config(c):
    config_path().write_text(json.dumps(c, indent=2))
    return c


def db_path():
    return home_data() / "locdepintel.sqlite3"


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


# Only inspect package metadata and trusted lockfiles; do NOT run the environment's python executable.
def normalize_name(ecosystem, name):
    """PyPI names compare case-insensitively with runs of - _ . equivalent (PEP 503)."""
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name


EXCLUDED_DIRS = {
    ".git",
    ".cache",
    ".npm",
    ".next",
    ".nuxt",
    ".venv-cache",
    "dist",
    "build",
    "coverage",
    ".tox",
    ".mypy_cache",
    "__pycache__",
    "site-packages",
    "node_modules",
    ".rustup",
    ".cargo",
    ".gradle",
}


def discover_detailed(roots, max_depth=5, max_dirs=30000):
    """Bounded walk of the configured roots. Never follows symlinks.

    Returns ``(environments, warnings, complete_roots)``. ``complete_roots`` holds the
    resolved roots that were walked to the end; only inside those can a missing
    environment safely be treated as removed.
    """
    environments = []
    visited = 0
    warnings = []
    complete_roots = set()
    seen_roots = set()
    for root in roots:
        root = pathlib.Path(root).expanduser().resolve()
        if str(root) in seen_roots:
            continue
        seen_roots.add(str(root))
        if not root.is_dir():
            warnings.append(f"Root unavailable: {root}")
            continue
        for parent, dirs, files in os.walk(root, followlinks=False):
            visited += 1
            if visited > max_dirs:
                warnings.append("Directory cap reached; discovery incomplete")
                return environments, warnings, complete_roots
            here = pathlib.Path(parent)
            depth = len(here.relative_to(root).parts)
            dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS and not (here / d).is_symlink()]
            if depth >= max_depth:
                dirs[:] = []
            if "pyvenv.cfg" in files:
                environments.append((str(here), "Python venv", python_env(here)))
                dirs[:] = []
                continue
            if "conda-meta" in dirs:
                environments.append((str(here), "Python conda", python_env(here)))
                # A conda base install keeps further environments in envs/.
                dirs[:] = [d for d in dirs if d == "envs"]
                continue
            project = parsers.project_lockfiles(here, set(files))
            if project:
                environments.append((str(here), project[0], project[1]))
        complete_roots.add(str(root))
    return environments, warnings, complete_roots


def discover(roots, max_depth=5, max_dirs=30000):
    """Backwards-compatible wrapper returning ``(environments, warnings)``."""
    environments, warnings, _ = discover_detailed(roots, max_depth, max_dirs)
    return environments, warnings


def _under(path, root):
    try:
        return pathlib.PurePath(path).is_relative_to(root)
    except (TypeError, ValueError):
        return False


def classify_unseen(env_path, roots, complete_roots):
    """Decide what an environment that was not found in this scan means.

    * ``out-of-scope``: not under any configured root any more (root removed in settings).
    * ``missing``: under a root that was fully walked, so it really is gone.
    * ``unknown``: under a root that was unavailable or cut off; keep last known data.
    """
    containing = [r for r in roots if _under(env_path, r)]
    if not containing:
        return "out-of-scope"
    if any(r in complete_roots for r in containing):
        return "missing"
    return "unknown"


def global_environments(candidates=None):
    """Opt-in: well-known global npm, Python and pipx locations that exist on this machine."""
    out = []
    for path, kind in parsers.global_candidates() if candidates is None else candidates:
        if pathlib.Path(path).is_dir():
            out.append((path, kind, parsers.read_global(path, kind)))
    return out


EVENT_SQL = (
    "INSERT INTO events(occurred,kind,env,ecosystem,name,version,description) "
    "VALUES (?,?,?,?,?,?,?)"
)


def scan(c=None):
    c = c or load_config()
    started = timestamp()
    roots = [str(pathlib.Path(r).expanduser().resolve()) for r in c.get("roots", [])]
    with db() as con:
        sid = con.execute(
            "INSERT INTO scans(started,status) VALUES (?,?)", (started, "running")
        ).lastrowid
        try:
            found, warnings, complete_roots = discover_detailed(
                roots, int(c.get("max_depth", 5)), int(c.get("max_dirs", 30000))
            )
            if c.get("include_global"):
                candidates = parsers.global_candidates()
                found += global_environments(candidates)
                # Global locations count as fully read scopes, so one that disappears is
                # "missing" and turning the option off makes them "out-of-scope".
                roots = roots + [path for path, _ in candidates]
                complete_roots = complete_roots | {path for path, _ in candidates}
            now = timestamp()
            active = {}
            envpaths = set()
            for path, ecosystem, records in found:
                envpaths.add(path)
                count = 0
                for eco, name, ver, direct in records:
                    name = name.strip()
                    ver = ver.strip()
                    if not name or not ver or len(name) > 220 or len(ver) > 120:
                        continue
                    key = (path, eco, normalize_name(eco, name), ver)
                    active[key] = direct
                    count += 1
                con.execute(
                    "INSERT INTO envs VALUES (?,?,?,?,?) ON CONFLICT(path) DO UPDATE SET "
                    "ecosystem=excluded.ecosystem,last_seen=excluded.last_seen,"
                    "state=excluded.state,package_count=excluded.package_count",
                    (path, ecosystem, now, "monitored", count),
                )
            old = {
                tuple(row)
                for row in con.execute(
                    "SELECT env,ecosystem,name,version FROM inventory WHERE active=1"
                )
            }
            for key, direct in active.items():
                if key not in old:
                    con.execute(
                        EVENT_SQL, (now, "added", *key, "First observed; install time unknown")
                    )
                con.execute(
                    "INSERT INTO inventory(env,ecosystem,name,version,direct,discovered,seen,active)"
                    " VALUES (?,?,?,?,?,?,?,1) ON CONFLICT(env,ecosystem,name,version) DO UPDATE"
                    " SET seen=excluded.seen,active=1,direct=excluded.direct",
                    (*key, direct, now, now),
                )

            # Retire what was not seen, but only when we can be sure why it was not seen.
            removed = out_of_scope = 0
            for key in old - active.keys():
                env = key[0]
                if env in envpaths:
                    verdict = "missing"  # environment read fine, this package is gone from it
                else:
                    verdict = classify_unseen(env, roots, complete_roots)
                if verdict == "unknown":
                    continue
                con.execute(
                    "UPDATE inventory SET active=0 "
                    "WHERE env=? AND ecosystem=? AND name=? AND version=?",
                    key,
                )
                if verdict == "missing":
                    removed += 1
                    note = "No longer found in observed environment; not proof of uninstall"
                    con.execute(EVENT_SQL, (now, "removed", *key, note))
                else:
                    out_of_scope += 1
                    note = "Folder no longer in scan scope; stopped monitoring"
                    con.execute(EVENT_SQL, (now, "out-of-scope", *key, note))

            for (env,) in con.execute("SELECT path FROM envs WHERE state='monitored'").fetchall():
                if env in envpaths:
                    continue
                verdict = classify_unseen(env, roots, complete_roots)
                if verdict != "unknown":
                    con.execute("UPDATE envs SET state=? WHERE path=?", (verdict, env))

            # Findings only make sense for packages that are still monitored.
            con.execute(
                "UPDATE findings SET active=0 WHERE active=1 AND NOT EXISTS ("
                " SELECT 1 FROM inventory i WHERE i.active=1 AND i.env=findings.env"
                " AND i.ecosystem=findings.ecosystem AND i.name=findings.name"
                " AND i.version=findings.version)"
            )
            con.execute(
                "UPDATE scans SET ended=?,status=?,packages=?,error=? WHERE id=?",
                (now, "partial" if warnings else "ok", len(active), "\n".join(warnings), sid),
            )
            return {
                "scan_id": sid,
                "environments": len(found),
                "packages": len(active),
                "added": len(active.keys() - old),
                "removed": removed,
                "out_of_scope": out_of_scope,
                "warnings": warnings,
            }
        except Exception as ex:
            con.execute(
                "UPDATE scans SET ended=?,status=?,error=? WHERE id=?",
                (timestamp(), "error", str(ex), sid),
            )
            raise


def request_json(url, payload=None, timeout=20):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "User-Agent": USER_AGENT,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST" if data else "GET",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


OSV_DETAIL_WORKERS = 8


def _fetch_one(aid):
    try:
        return aid, request_json("https://api.osv.dev/v1/vulns/" + urllib.parse.quote(aid, safe=""))
    except (OSError, ValueError, urllib.error.URLError):
        return aid, {}  # summary falls back to a generic label; the match itself still counts


ADVISORY_CACHE_HOURS = 24


def fetch_advisory_details(ids):
    """OSV advisory records, from a 24 h local cache or downloaded concurrently.

    The cache keeps scheduled runs from re-downloading every advisory; 24 h still picks
    up withdrawals and summary changes the next day. Failed downloads are not cached.
    """
    if not ids:
        return {}
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=ADVISORY_CACHE_HOURS)).isoformat()
    details = {}
    with db() as con:
        for row in con.execute(
            "SELECT id, payload FROM advisory_cache WHERE fetched > ?", (cutoff,)
        ):
            if row["id"] in ids:
                try:
                    details[row["id"]] = json.loads(row["payload"])
                except ValueError:
                    pass
    missing = sorted(set(ids) - details.keys())
    if missing:
        with ThreadPoolExecutor(max_workers=OSV_DETAIL_WORKERS) as pool:
            fetched = dict(pool.map(_fetch_one, missing))
        now = timestamp()
        with db() as con:
            for aid, payload in fetched.items():
                if payload:
                    con.execute(
                        "INSERT INTO advisory_cache(id, fetched, payload) VALUES (?,?,?) "
                        "ON CONFLICT(id) DO UPDATE SET fetched=excluded.fetched,"
                        "payload=excluded.payload",
                        (aid, now, json.dumps(payload)),
                    )
        details.update(fetched)
    return details


def assess(batch_size=100):
    """Exact package/version OSV checks; failures never erase earlier findings or produce false clean state."""
    with db() as con:
        records = list(
            con.execute(
                "SELECT DISTINCT ecosystem,name,version FROM inventory WHERE active=1 AND ecosystem IN ('PyPI','npm')"
            )
        )
        if not records:
            con.execute(
                "INSERT INTO checks(timestamp,state,note,packages) VALUES (?,?,?,?)",
                (timestamp(), "no-packages", "No discovered packages to check", 0),
            )
            return {"state": "no-packages", "checked": 0, "findings": 0}
        findings = {}
        checked = 0
        try:
            for pos in range(0, len(records), batch_size):
                group = records[pos : pos + batch_size]
                pending = [
                    (
                        {
                            "package": {"name": r["name"], "ecosystem": r["ecosystem"]},
                            "version": r["version"],
                        },
                        (r["ecosystem"], r["name"], r["version"]),
                    )
                    for r in group
                ]
                rounds = 0
                while pending and rounds < 12:
                    rounds += 1
                    output = request_json(
                        "https://api.osv.dev/v1/querybatch", {"queries": [q for q, k in pending]}
                    )
                    results = output.get("results", [])
                    if len(results) != len(pending):
                        raise ValueError("OSV response length mismatch")
                    later = []
                    for (q, key), res in zip(pending, results, strict=True):
                        findings.setdefault(key, set()).update(
                            v["id"] for v in res.get("vulns", []) if v.get("id")
                        )
                        if res.get("next_page_token"):
                            later.append((dict(q, page_token=res["next_page_token"]), key))
                    pending = later
                if pending:
                    raise ValueError("OSV pagination limit reached; check incomplete")
                checked += len(group)
            # Fetch advisory details after all batch calls have succeeded.
            unique_ids = {aid for matches in findings.values() for aid in matches}
            detail = fetch_advisory_details(unique_ids)
            now = timestamp()
            con.execute("UPDATE findings SET active=0")
            for (eco, name, ver), matched in findings.items():
                for aid in matched:
                    info = detail.get(aid, {})
                    if info.get("withdrawn"):
                        continue
                    kind = (
                        "malware"
                        if aid.startswith("MAL-")
                        or info.get("database_specific", {}).get("malware")
                        else "vulnerability"
                    )
                    summary = str(
                        info.get("summary")
                        or (
                            "Published malicious-package advisory"
                            if kind == "malware"
                            else "Published security advisory"
                        )
                    )[:700]
                    url = "https://osv.dev/vulnerability/" + aid
                    for row in con.execute(
                        "SELECT env FROM inventory WHERE active=1 AND ecosystem=? AND name=? AND version=?",
                        (eco, name, ver),
                    ):
                        key = (row["env"], eco, name, ver, aid)
                        prev = con.execute(
                            "SELECT id FROM findings WHERE env=? AND ecosystem=? AND name=? AND version=? AND advisory=?",
                            key,
                        ).fetchone()
                        con.execute(
                            "INSERT INTO findings(env,ecosystem,name,version,advisory,kind,summary,url,first_seen,last_seen,active) VALUES (?,?,?,?,?,?,?,?,?,?,1) ON CONFLICT(env,ecosystem,name,version,advisory) DO UPDATE SET last_seen=excluded.last_seen,active=1,summary=excluded.summary,kind=excluded.kind",
                            (*key, kind, summary, url, now, now),
                        )
                        if not prev:
                            con.execute(
                                "INSERT INTO events(occurred,kind,env,ecosystem,name,version,description) VALUES (?,?,?,?,?,?,?)",
                                (
                                    now,
                                    "malware-alert" if kind == "malware" else "advisory",
                                    row["env"],
                                    eco,
                                    name,
                                    ver,
                                    aid,
                                ),
                            )
            con.execute(
                "INSERT INTO checks(timestamp,state,note,packages) VALUES (?,?,?,?)",
                (now, "ok", f"{len(unique_ids)} unique OSV advisories", checked),
            )
            return {
                "state": "ok",
                "checked": checked,
                "advisories": len(unique_ids),
                "active_findings": con.execute(
                    "SELECT count(*) FROM findings WHERE active=1"
                ).fetchone()[0],
            }
        except Exception as ex:
            con.execute(
                "INSERT INTO checks(timestamp,state,note,packages) VALUES (?,?,?,?)",
                (timestamp(), "error", str(ex)[:600], checked),
            )
            return {"state": "error", "checked": checked, "error": str(ex)}


def state():
    with db() as con:

        def obj(q, args=()):
            return [dict(r) for r in con.execute(q, args)]

        return {
            "stats": {
                "environments": con.execute(
                    "SELECT count(*) FROM envs WHERE state='monitored'"
                ).fetchone()[0],
                "packages": con.execute("SELECT count(*) FROM inventory WHERE active=1").fetchone()[
                    0
                ],
                "malware": con.execute(
                    "SELECT count(*) FROM findings WHERE active=1 AND kind='malware'"
                ).fetchone()[0],
                "vulnerabilities": con.execute(
                    "SELECT count(*) FROM findings WHERE active=1 AND kind='vulnerability'"
                ).fetchone()[0],
            },
            "scans": obj("SELECT * FROM scans ORDER BY id DESC LIMIT 8"),
            "checks": obj("SELECT * FROM checks ORDER BY id DESC LIMIT 8"),
            "envs": obj("SELECT * FROM envs ORDER BY path LIMIT 200"),
            "findings": obj(
                "SELECT * FROM findings WHERE active=1 ORDER BY (kind='malware') DESC,id DESC LIMIT 500"
            ),
            "events": obj("SELECT * FROM events ORDER BY id DESC LIMIT 100"),
            "config": load_config(),
        }


def inventory(env=None, limit=25000):
    with db() as con:
        if env:
            return [
                dict(r)
                for r in con.execute(
                    "SELECT * FROM inventory WHERE active=1 AND env=? ORDER BY name LIMIT ?",
                    (env, limit),
                )
            ]
        return [
            dict(r)
            for r in con.execute(
                "SELECT * FROM inventory WHERE active=1 ORDER BY env,name LIMIT ?", (limit,)
            )
        ]


def export():
    return {"generated": timestamp(), "state": state(), "inventory": inventory(limit=200000)}


def package_intelligence(ecosystem, name, force=False):
    """On-demand deps.dev metadata. Does not score safety or propose unverified alternatives."""
    if ecosystem not in ("PyPI", "npm") or not isinstance(name, str) or not name or len(name) > 220:
        raise ValueError("Unsupported package")
    system = "PYPI" if ecosystem == "PyPI" else "NPM"
    from datetime import timedelta

    with db() as con:
        row = con.execute(
            "SELECT fetched,payload FROM registry_cache WHERE ecosystem=? AND name=?",
            (ecosystem, name),
        ).fetchone()
        if row and not force:
            try:
                if datetime.now(timezone.utc) - datetime.fromisoformat(row["fetched"]) < timedelta(
                    hours=6
                ):
                    data = json.loads(row["payload"])
                    data["cached"] = True
                    return data
            except (ValueError, TypeError):
                pass
    url = (
        "https://api.deps.dev/v3/systems/"
        + system
        + "/packages/"
        + urllib.parse.quote(name, safe="")
    )
    response = request_json(url, timeout=12)
    versions = response.get("versions", [])
    if not isinstance(versions, list):
        raise ValueError("Unexpected package intelligence response")
    default = next((x for x in versions if x.get("isDefault")), None)
    recent = sorted(
        (x for x in versions if isinstance(x, dict)),
        key=lambda x: x.get("publishedAt") or "",
        reverse=True,
    )[:8]
    output = {
        "ecosystem": ecosystem,
        "name": name,
        "default_version": ((default or {}).get("versionKey") or {}).get("version"),
        "default_published": (default or {}).get("publishedAt"),
        "recent_versions": [
            {
                "version": (x.get("versionKey") or {}).get("version"),
                "published": x.get("publishedAt"),
                "deprecated": bool(x.get("isDeprecated")),
            }
            for x in recent
        ],
        "source": "deps.dev",
        "source_url": "https://deps.dev/"
        + ("pypi" if ecosystem == "PyPI" else "npm")
        + "/"
        + urllib.parse.quote(name, safe=""),
        "retrieved": timestamp(),
        "cached": False,
        "warning": "Newer does not necessarily mean secure or compatible. Verify advisories and test upgrades.",
    }
    with db() as con:
        con.execute(
            "INSERT INTO registry_cache(ecosystem,name,fetched,payload) VALUES (?,?,?,?) ON CONFLICT(ecosystem,name) DO UPDATE SET fetched=excluded.fetched,payload=excluded.payload",
            (ecosystem, name, timestamp(), json.dumps(output)),
        )
    return output


# Global advisory discovery is independent of local vulnerability exposure matching.
# GitHub Advisory Database public REST endpoint, only standard-library HTTPS.
def normalize_pulse_advisory(item):
    if not isinstance(item, dict) or not item.get("ghsa_id"):
        return None
    affected = []
    for v in item.get("vulnerabilities") or []:
        if not isinstance(v, dict):
            continue
        p = v.get("package") or {}
        if not isinstance(p, dict) or not p.get("name"):
            continue
        eco = {"pip": "PyPI", "npm": "npm"}.get(
            str(p.get("ecosystem", "")).lower(), str(p.get("ecosystem", ""))
        )
        affected.append(
            {
                "ecosystem": eco,
                "name": str(p["name"])[:220],
                "range": str(v.get("vulnerable_version_range") or "")[:500],
                "fixed": str(v.get("first_patched_version") or "")[:140],
            }
        )
    if not affected:
        return None
    ident = str(item["ghsa_id"])[:110]
    return {
        "id": ident,
        "kind": "malware" if item.get("type") == "malware" else "vulnerability",
        "severity": str(item.get("severity") or "unknown")[:32],
        "summary": str(item.get("summary") or "No summary supplied")[:600],
        "url": "https://github.com/advisories/" + urllib.parse.quote(ident, safe=""),
        "published": str(item.get("published_at") or ""),
        "updated": str(item.get("updated_at") or ""),
        "affected": affected,
    }


def sync_pulse(per_type=60):
    """Retrieve newest public GHSA malware/reviewed disclosures. Never synthesize live results."""
    per_type = max(1, min(int(per_type), 100))
    gathered = {}
    failures = []
    for typ in ("malware", "reviewed"):
        params = urllib.parse.urlencode(
            {"type": typ, "sort": "published", "direction": "desc", "per_page": per_type}
        )
        try:
            req = urllib.request.Request(
                "https://api.github.com/advisories?" + params,
                headers={
                    "Accept": "application/vnd.github+json",
                    "User-Agent": USER_AGENT,
                    "X-GitHub-Api-Version": "2026-03-10",
                },
            )
            with urllib.request.urlopen(req, timeout=18) as res:
                records = json.load(res)
            if not isinstance(records, list):
                raise ValueError("Unexpected advisory response")
            for item in records:
                norm = normalize_pulse_advisory(item)
                if norm:
                    gathered[norm["id"]] = norm
        except (OSError, ValueError, urllib.error.HTTPError) as exc:
            failures.append(typ + ": " + str(exc)[:220])
    now = timestamp()
    with db() as con:
        for a in gathered.values():
            con.execute(
                "INSERT INTO pulse_advisories(id,kind,severity,summary,url,published,updated,fetched,affected_json) VALUES (?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET kind=excluded.kind,severity=excluded.severity,summary=excluded.summary,url=excluded.url,published=excluded.published,updated=excluded.updated,fetched=excluded.fetched,affected_json=excluded.affected_json",
                (
                    a["id"],
                    a["kind"],
                    a["severity"],
                    a["summary"],
                    a["url"],
                    a["published"],
                    a["updated"],
                    now,
                    json.dumps(a["affected"]),
                ),
            )
        status = "partial" if failures and gathered else "error" if failures else "ok"
        con.execute(
            "INSERT INTO pulse_sync(timestamp,state,count,note) VALUES (?,?,?,?)",
            (now, status, len(gathered), "; ".join(failures)),
        )
    return {"state": status, "fetched": len(gathered), "errors": failures, "time": now}


def pulse(limit=160):
    """Never infer local affected-version status from package name alone."""
    with db() as con:
        rows = con.execute(
            "SELECT * FROM pulse_advisories ORDER BY published DESC LIMIT ?",
            (min(max(1, int(limit)), 300),),
        ).fetchall()
        # Exact local advisory match established by independent OSV version-aware checks.
        active = {
            (r["advisory"], r["ecosystem"], normalize_name(r["ecosystem"], r["name"]))
            for r in con.execute(
                "SELECT DISTINCT advisory,ecosystem,name FROM findings WHERE active=1"
            )
        }
        inventory_names = {
            (r["ecosystem"], normalize_name(r["ecosystem"], r["name"]))
            for r in con.execute("SELECT DISTINCT ecosystem,name FROM inventory WHERE active=1")
        }
        out = []
        for r in rows:
            a = dict(r)
            a["affected"] = json.loads(a.pop("affected_json"))
            a["local_status"] = (
                "affected"
                if any(
                    (a["id"], p["ecosystem"], normalize_name(p["ecosystem"], p["name"])) in active
                    for p in a["affected"]
                )
                else (
                    "package-present"
                    if any(
                        (p["ecosystem"], normalize_name(p["ecosystem"], p["name"]))
                        in inventory_names
                        for p in a["affected"]
                    )
                    else "not-detected"
                )
            )
            out.append(a)
        last = con.execute("SELECT * FROM pulse_sync ORDER BY id DESC LIMIT 1").fetchone()
        check = con.execute(
            "SELECT timestamp,state FROM checks ORDER BY id DESC LIMIT 1"
        ).fetchone()
    return {
        "advisories": out,
        "last_sync": dict(last) if last else None,
        "last_local_check": dict(check) if check else None,
        "caveat": "Local affected means a current OSV version-aware matching finding with the same advisory ID; package-present means matching package name only and requires a local check. Not detected is limited to monitored environments.",
    }


def grouped_findings():
    with db() as con:
        rows = con.execute(
            "SELECT env,ecosystem,name,version,advisory,kind,summary,url,first_seen,last_seen FROM findings WHERE active=1 ORDER BY ecosystem,name,version,advisory,env"
        ).fetchall()
    grouped = {}
    for row in rows:
        r = dict(row)
        k = (r["ecosystem"], normalize_name(r["ecosystem"], r["name"]), r["version"])
        if k not in grouped:
            grouped[k] = {
                "ecosystem": r["ecosystem"],
                "name": r["name"],
                "version": r["version"],
                "advisories": {},
                "locations": set(),
                "kind": "vulnerability",
            }
        g = grouped[k]
        g["locations"].add(r["env"])
        g["kind"] = "malware" if r["kind"] == "malware" else g["kind"]
        a = g["advisories"].setdefault(
            r["advisory"],
            {
                "id": r["advisory"],
                "kind": r["kind"],
                "summary": r["summary"],
                "url": r["url"],
                "locations": set(),
            },
        )
        a["locations"].add(r["env"])
    out = []
    for group in grouped.values():
        group["locations"] = sorted(group["locations"])
        group["advisories"] = [
            dict(a, locations=sorted(a["locations"])) for a in group["advisories"].values()
        ]
        group["advisory_count"] = len(group["advisories"])
        group["installation_count"] = len(group["locations"])
        out.append(group)
    return sorted(
        out,
        key=lambda g: (
            g["kind"] != "malware",
            -g["installation_count"],
            g["name"].lower(),
            g["version"],
        ),
    )


def environment_folder(path):
    """Classify top-level user folder without disclosing more path than locally stored."""
    home = pathlib.Path.home()
    try:
        parts = pathlib.Path(path).expanduser().relative_to(home).parts
    except ValueError:
        return "Other locations"
    if not parts:
        return "Home"
    return parts[0] if not parts[0].startswith(".") else "Hidden locations"


def overview():
    """Read-only aggregate from existing local persistence; no new DB schema."""
    with db() as con:
        stats = {
            "installed_entries": con.execute(
                "SELECT COUNT(*) FROM inventory WHERE active=1"
            ).fetchone()[0],
            "environments": con.execute(
                "SELECT COUNT(*) FROM envs WHERE state='monitored'"
            ).fetchone()[0],
            "unique_packages": con.execute(
                "SELECT COUNT(*) FROM (SELECT DISTINCT ecosystem,name,version FROM inventory WHERE active=1)"
            ).fetchone()[0],
        }
        scans = [dict(r) for r in con.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 2")]
        checks = [dict(r) for r in con.execute("SELECT * FROM checks ORDER BY id DESC LIMIT 3")]
        envs = [
            dict(r, folder=environment_folder(r["path"]))
            for r in con.execute(
                "SELECT * FROM envs WHERE state='monitored' ORDER BY path LIMIT 500"
            )
        ]
        events = [dict(r) for r in con.execute("SELECT * FROM events ORDER BY id DESC LIMIT 15")]
        good_checks = [c for c in checks if c["state"] == "ok"]
        previous = good_checks[1]["timestamp"] if len(good_checks) > 1 else None
        new_records = (
            [
                dict(x)
                for x in con.execute(
                    "SELECT DISTINCT ecosystem,name,version FROM findings WHERE active=1 AND first_seen>?",
                    (previous,),
                )
            ]
            if previous
            else []
        )
        new_findings = (
            con.execute(
                "SELECT COUNT(*) FROM (SELECT ecosystem,name,version,advisory FROM findings WHERE active=1 AND first_seen>? GROUP BY ecosystem,name,version,advisory)",
                (previous,),
            ).fetchone()[0]
            if previous
            else None
        )
    groups = grouped_findings()
    stats.update(
        {
            "affected_packages": len(groups),
            "malware_packages": sum(g["kind"] == "malware" for g in groups),
            "affected_installations": sum(g["installation_count"] for g in groups),
            "new_advisory_matches": new_findings,
        }
    )
    return {
        "stats": stats,
        "scans": scans,
        "checks": checks,
        "environments": envs,
        "action_queue": groups[:15],
        "history": events,
        "new_packages": new_records,
        "config": load_config(),
        "generated": timestamp(),
        "scope_note": "Only discovered monitored paths are covered. No advisory match does not mean safe.",
    }
