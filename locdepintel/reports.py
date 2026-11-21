"""Read-only views for the dashboard and the CLI (plus first-run onboarding state)."""

import json
import pathlib

from .scanner import normalize_name
from .settings import load_config, save_config, suggested_roots, timestamp
from .store import db


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
                "SELECT *"
                " FROM findings WHERE active=1 ORDER BY (kind='malware') DESC,id DESC LIMIT 500"
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
        "caveat": (
            "Local affected means a current OSV version-aware matching finding with the same "
            "advisory ID; package-present means matching package name only and requires a "
            "local check. Not detected is limited to monitored environments."
        ),
    }


def grouped_findings():
    with db() as con:
        rows = con.execute(
            "SELECT env,ecosystem,name,version,advisory,kind,summary,url,first_seen,"
            "last_seen FROM findings WHERE active=1 ORDER BY ecosystem,name,version,advisory,env"
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
                "SELECT COUNT(*) FROM (SELECT DISTINCT ecosystem,name,version"
                " FROM inventory WHERE active=1)"
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
                    "SELECT DISTINCT ecosystem,name,version"
                    " FROM findings WHERE active=1 AND first_seen>?",
                    (previous,),
                )
            ]
            if previous
            else []
        )
        new_findings = (
            con.execute(
                "SELECT COUNT(*) FROM (SELECT ecosystem,name,version,advisory"
                " FROM findings"
                " WHERE active=1 AND first_seen>? GROUP BY ecosystem,name,version,advisory)",
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
        "scope_note": (
            "Only discovered monitored paths are covered. " "No advisory match does not mean safe."
        ),
    }
