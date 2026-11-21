"""Read-only inventory and OSV monitoring. Only package metadata is read; project code is never imported."""

import importlib.metadata
import json
import os
import pathlib
import re
import sqlite3
import sys
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from datetime import datetime, timezone

from . import __version__

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


@contextmanager
def db():
    conn = sqlite3.connect(db_path(), timeout=20, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=10000")
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY, started TEXT, ended TEXT, status TEXT, error TEXT, packages INTEGER DEFAULT 0, checked INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS inventory(env TEXT NOT NULL, ecosystem TEXT NOT NULL, name TEXT NOT NULL, version TEXT NOT NULL, direct TEXT, discovered TEXT NOT NULL, seen TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, PRIMARY KEY(env,ecosystem,name,version));
    CREATE INDEX IF NOT EXISTS idx_inv_active ON inventory(active,ecosystem,name,version);
    CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, occurred TEXT, kind TEXT, env TEXT, ecosystem TEXT, name TEXT, version TEXT, description TEXT);
    CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY, env TEXT, ecosystem TEXT, name TEXT, version TEXT, advisory TEXT, kind TEXT, summary TEXT, url TEXT, first_seen TEXT, last_seen TEXT, active INTEGER DEFAULT 1, UNIQUE(env,ecosystem,name,version,advisory));
    CREATE TABLE IF NOT EXISTS checks(id INTEGER PRIMARY KEY, timestamp TEXT, state TEXT, note TEXT, packages INTEGER);
    CREATE TABLE IF NOT EXISTS envs(path TEXT PRIMARY KEY, ecosystem TEXT, last_seen TEXT, state TEXT, package_count INTEGER);
    CREATE TABLE IF NOT EXISTS registry_cache(ecosystem TEXT, name TEXT, fetched TEXT, payload TEXT, PRIMARY KEY(ecosystem,name));
    CREATE TABLE IF NOT EXISTS pulse_advisories(id TEXT PRIMARY KEY, kind TEXT, severity TEXT, summary TEXT, url TEXT, published TEXT, updated TEXT, fetched TEXT, affected_json TEXT);
    CREATE TABLE IF NOT EXISTS pulse_sync(id INTEGER PRIMARY KEY, timestamp TEXT, state TEXT, count INTEGER, note TEXT);
    """)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


# Only inspect package metadata and trusted lockfiles; do NOT run the environment's python executable.
def metadata_name_version(path):
    try:
        s = (path / "METADATA").read_text(encoding="utf-8", errors="replace")[:25000]
        n = re.search(r"^Name:\s*(.+)$", s, re.M | re.I)
        v = re.search(r"^Version:\s*(.+)$", s, re.M | re.I)
        if n and v:
            return (n.group(1).strip(), v.group(1).strip())
    except (OSError, UnicodeError):
        pass
    return None


def python_env(path):
    records = []
    seen = set()
    paths = []
    for rel in ["lib", "Lib"]:
        top = path / rel
        if not top.is_dir():
            continue
        try:
            if rel == "Lib":
                paths.append(top / "site-packages")
            else:
                for p in top.iterdir():
                    if p.is_dir() and p.name.startswith("python"):
                        paths.append(p / "site-packages")
        except OSError:
            continue
    for directory in paths:
        if not directory.is_dir():
            continue
        try:
            for d in directory.iterdir():
                if not d.name.endswith(".dist-info") or not d.is_dir():
                    continue
                nv = metadata_name_version(d)
                if not nv:
                    continue
                name, ver = nv
                key = (name.lower().replace("_", "-"), ver)
                if key not in seen:
                    records.append(("PyPI", name, ver, "unknown"))
                    seen.add(key)
        except OSError:
            pass
    return records


def npm_lock(project):
    f = project / "package-lock.json"
    out = []
    try:
        package_json = json.loads((project / "package.json").read_text(encoding="utf-8"))
        declared = set()
        for section in (
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies",
        ):
            declared.update(package_json.get(section, {}))
    except (OSError, ValueError, TypeError):
        declared = set()
    try:
        data = json.loads(f.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if isinstance(data.get("packages"), dict):
        for k, v in data["packages"].items():
            if not k or not isinstance(v, dict) or not v.get("version"):
                continue
            # Keys without node_modules/ are workspace members or local folders (e.g. "packages/app").
            # They are not public registry packages; querying OSV with them leaks internal names.
            if "node_modules/" not in k or v.get("link"):
                continue
            # Nested packages can carry multiple versions of the same dependency.
            name = k.rsplit("node_modules/", 1)[-1] if "node_modules/" in k else k
            if not name or name.startswith("../"):
                continue
            if name.startswith("@") and "/" not in name:
                continue
            out.append(
                (
                    "npm",
                    name,
                    str(v["version"]),
                    (
                        "direct"
                        if (
                            k.startswith("node_modules/")
                            and k.count("node_modules/") == 1
                            and name in declared
                        )
                        else "transitive" if declared else "unknown"
                    ),
                )
            )
    else:
        # npm lockfile v1 nested dependency objects
        def walk(d):
            if not isinstance(d, dict):
                return
            for name, info in d.items():
                if not isinstance(info, dict):
                    continue
                if info.get("version"):
                    out.append(("npm", name, str(info["version"]), "unknown"))
                walk(info.get("dependencies", {}))

        walk(data.get("dependencies", {}))
    return out


def discover(roots, max_depth=5, max_dirs=30000):
    """Conservative bounded scan, no symlinks followed, skips huge vendor/system dirs."""
    exclusions = {
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
    environments = []
    visited = 0
    warnings = []
    seen_roots = set()
    for root in roots:
        root = pathlib.Path(root).expanduser().resolve()
        if str(root) in seen_roots:
            continue
        seen_roots.add(str(root))
        if not root.exists() or not root.is_dir():
            warnings.append(f"Root unavailable: {root}")
            continue
        for parent, dirs, files in os.walk(root, followlinks=False):
            visited += 1
            depth = len(pathlib.Path(parent).relative_to(root).parts)
            if visited > max_dirs:
                warnings.append("Directory cap reached; discovery incomplete")
                return environments, warnings
            dirs[:] = [
                d
                for d in dirs
                if d not in exclusions and not (pathlib.Path(parent) / d).is_symlink()
            ]
            if depth >= max_depth:
                dirs[:] = []
            here = pathlib.Path(parent)
            if "pyvenv.cfg" in files:
                environments.append((str(here), "Python", python_env(here)))
                dirs[:] = []
                continue
            if "package-lock.json" in files:
                environments.append((str(here), "npm", npm_lock(here)))
    return environments, warnings


def global_packages():
    out = []
    # only scans this interpreter, never imports distributions
    try:
        for x in importlib.metadata.distributions():
            name = x.metadata.get("Name")
            ver = x.version
            if name and ver:
                out.append(("PyPI", name, ver, "unknown"))
    except Exception:
        pass
    return [("Current Python interpreter: " + sys.executable, "Python", out)]


def scan(c=None):
    c = c or load_config()
    started = timestamp()
    with db() as con:
        sid = con.execute(
            "INSERT INTO scans(started,status) VALUES (?,?)", (started, "running")
        ).lastrowid
        try:
            found, warnings = discover(
                c.get("roots", []), int(c.get("max_depth", 5)), int(c.get("max_dirs", 30000))
            )
            if c.get("include_global"):
                found += global_packages()
            now = timestamp()
            active = {}
            envpaths = set()
            total = 0
            for path, ecosystem, records in found:
                envpaths.add(path)
                count = 0
                for eco, name, ver, direct in records:
                    name = name.strip()
                    ver = ver.strip()
                    if not name or not ver or len(name) > 220 or len(ver) > 120:
                        continue
                    key = (
                        path,
                        eco,
                        name.lower().replace("_", "-") if eco == "PyPI" else name,
                        ver,
                    )
                    active[key] = direct
                    count += 1
                    total += 1
                con.execute(
                    "INSERT INTO envs VALUES (?,?,?,?,?) ON CONFLICT(path) DO UPDATE SET last_seen=excluded.last_seen,state=excluded.state,package_count=excluded.package_count",
                    (path, ecosystem, now, "monitored", count),
                )
            old = {
                tuple(row[:4])
                for row in con.execute(
                    "SELECT env,ecosystem,name,version FROM inventory WHERE active=1"
                )
            }
            for key, direct in active.items():
                if key not in old:
                    con.execute(
                        "INSERT INTO events(occurred,kind,env,ecosystem,name,version,description) VALUES (?,?,?,?,?,?,?)",
                        (now, "added", *key, "First observed; installation time not verified"),
                    )
                con.execute(
                    "INSERT INTO inventory(env,ecosystem,name,version,direct,discovered,seen,active) VALUES (?,?,?,?,?,?,?,1) ON CONFLICT(env,ecosystem,name,version) DO UPDATE SET seen=excluded.seen,active=1,direct=excluded.direct",
                    (*key, direct, now, now),
                )
            # Avoid marking entries from out-of-scope roots removed, or on incomplete traversal.
            if not warnings:
                for key in old - active.keys():
                    if key[0] not in envpaths and not any(
                        str(key[0]).startswith(str(pathlib.Path(r).expanduser().resolve()) + os.sep)
                        or str(key[0]) == str(pathlib.Path(r).expanduser().resolve())
                        for r in c.get("roots", [])
                    ):
                        continue
                    con.execute(
                        "UPDATE inventory SET active=0 WHERE env=? AND ecosystem=? AND name=? AND version=?",
                        key,
                    )
                    con.execute(
                        "INSERT INTO events(occurred,kind,env,ecosystem,name,version,description) VALUES (?,?,?,?,?,?,?)",
                        (
                            now,
                            "removed",
                            *key,
                            "No longer found in observed environment; not proof of uninstall command",
                        ),
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
                "removed": len(old - active.keys()) if not warnings else 0,
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
                    for (q, key), res in zip(pending, results):
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
            ids = {id for matches in findings.values() for id in matches}
            detail = {}
            for aid in ids:
                try:
                    detail[aid] = request_json(
                        "https://api.osv.dev/v1/vulns/" + urllib.parse.quote(aid, safe="")
                    )
                except (OSError, ValueError, urllib.error.URLError):
                    detail[aid] = {}
            now = timestamp()
            con.execute("UPDATE findings SET active=0")
            for (eco, name, ver), ids in findings.items():
                for aid in ids:
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
                (now, "ok", f"{len(ids)} unique OSV advisories", checked),
            )
            return {
                "state": "ok",
                "checked": checked,
                "advisories": len(ids),
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
            (r["advisory"], r["ecosystem"], r["name"].lower().replace("_", "-"))
            for r in con.execute(
                "SELECT DISTINCT advisory,ecosystem,name FROM findings WHERE active=1"
            )
        }
        inventory_names = {
            (r["ecosystem"], r["name"].lower().replace("_", "-"))
            for r in con.execute("SELECT DISTINCT ecosystem,name FROM inventory WHERE active=1")
        }
        out = []
        for r in rows:
            a = dict(r)
            a["affected"] = json.loads(a.pop("affected_json"))
            a["local_status"] = (
                "affected"
                if any(
                    (a["id"], p["ecosystem"], p["name"].lower().replace("_", "-")) in active
                    for p in a["affected"]
                )
                else (
                    "package-present"
                    if any(
                        (p["ecosystem"], p["name"].lower().replace("_", "-")) in inventory_names
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
        k = (r["ecosystem"], r["name"].lower().replace("_", "-"), r["version"])
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
