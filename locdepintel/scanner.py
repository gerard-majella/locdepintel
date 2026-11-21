"""Discovery of environments on disk and the scan that keeps the inventory current.

A scan only reads files: package metadata and lockfiles. It never imports, executes or
installs anything it finds.
"""

import os
import pathlib
import re

from . import parsers
from .parsers import python_env
from .settings import load_config, timestamp
from .store import db


# Only package metadata and lockfiles are read; the environment's python is never run.
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
                    "INSERT INTO inventory(env,ecosystem,name,version,direct,discovered,seen,"
                    "active)"
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
