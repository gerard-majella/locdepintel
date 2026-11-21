"""Everything that talks to the network: OSV (advisory matching), deps.dev (version
lookups) and the GitHub Advisory Database (Threat Pulse).

Only package names and versions are sent. File paths never leave the machine.
"""

import json
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from . import __version__
from .settings import timestamp
from .store import db

USER_AGENT = f"LocDepIntel/{__version__} (+https://github.com/gerard-majella/locdepintel)"


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
    """Check every installed package version against OSV.

    A failed check never erases earlier findings and never reports a clean state.
    """
    with db() as con:
        records = list(
            con.execute(
                "SELECT DISTINCT ecosystem,name,version"
                " FROM inventory WHERE active=1 AND ecosystem IN ('PyPI','npm')"
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
                        "SELECT env"
                        " FROM inventory WHERE active=1 AND ecosystem=? AND name=? AND version=?",
                        (eco, name, ver),
                    ):
                        key = (row["env"], eco, name, ver, aid)
                        prev = con.execute(
                            "SELECT id"
                            " FROM findings"
                            " WHERE env=? AND ecosystem=? AND name=? AND version=? AND advisory=?",
                            key,
                        ).fetchone()
                        con.execute(
                            "INSERT INTO findings(env,ecosystem,name,version,advisory,kind,"
                            "summary,url,first_seen,last_seen,active)"
                            " VALUES (?,?,?,?,?,?,?,?,?,?,1)"
                            " ON CONFLICT(env,ecosystem,name,version,advisory)"
                            " DO UPDATE"
                            " SET last_seen=excluded.last_seen,active=1,summary=excluded.summary,"
                            "kind=excluded.kind",
                            (*key, kind, summary, url, now, now),
                        )
                        if not prev:
                            con.execute(
                                "INSERT INTO events(occurred,kind,env,ecosystem,name,version,"
                                "description) VALUES (?,?,?,?,?,?,?)",
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


def package_intelligence(ecosystem, name, force=False):
    """On-demand deps.dev metadata. Does not score safety or propose unverified alternatives."""
    if ecosystem not in ("PyPI", "npm") or not isinstance(name, str) or not name or len(name) > 220:
        raise ValueError("Unsupported package")
    system = "PYPI" if ecosystem == "PyPI" else "NPM"
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
        "warning": (
            "Newer does not necessarily mean secure or compatible. "
            "Verify advisories and test upgrades."
        ),
    }
    with db() as con:
        con.execute(
            "INSERT INTO registry_cache(ecosystem,name,fetched,payload)"
            " VALUES (?,?,?,?)"
            " ON CONFLICT(ecosystem,name)"
            " DO UPDATE SET fetched=excluded.fetched,payload=excluded.payload",
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
                "INSERT INTO pulse_advisories(id,kind,severity,summary,url,published,updated,"
                "fetched,affected_json) VALUES (?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(id)"
                " DO UPDATE"
                " SET kind=excluded.kind,severity=excluded.severity,summary=excluded.summary,"
                "url=excluded.url,published=excluded.published,updated=excluded.updated,"
                "fetched=excluded.fetched,affected_json=excluded.affected_json",
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
