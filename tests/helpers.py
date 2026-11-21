"""Shared test isolation. Every test that touches LocDepIntel data goes through here, so no
test can ever read or write the real data folder of the person running the suite."""

import json
import os
import pathlib
import tempfile
from unittest import mock

from locdepintel import advisories, settings


def _network_blocked(*args, **kwargs):
    raise AssertionError(f"Test tried to use the real network: {args[:1]}")


def isolate(testcase):
    """Give the test its own data folder and environment. Returns a fresh base folder."""
    tmp = tempfile.TemporaryDirectory()
    testcase.addCleanup(tmp.cleanup)
    base = pathlib.Path(tmp.name)
    data = base / "data"
    data.mkdir()
    patches = [
        mock.patch.object(settings, "home_data", lambda: data),
        # No test may reach the real internet; tests that need it use mock_network().
        mock.patch.object(advisories, "request_json", side_effect=_network_blocked),
        mock.patch("urllib.request.urlopen", side_effect=_network_blocked),
        mock.patch.dict(
            os.environ, {"XDG_DATA_HOME": str(base / "xdg"), "LOCALAPPDATA": str(base / "xdg")}
        ),
    ]
    for patcher in patches:
        patcher.start()
        testcase.addCleanup(patcher.stop)
    return base


def mock_network(testcase, side_effect):
    """Replace every OSV / deps.dev call made by LocDepIntel."""
    patcher = mock.patch.object(advisories, "request_json", side_effect=side_effect)
    fake = patcher.start()
    testcase.addCleanup(patcher.stop)
    return fake


def npm_project(path, packages, declared=None):
    """Write a package-lock.json (v3) project with ``{name: version}`` packages."""
    path = pathlib.Path(path)
    path.mkdir(parents=True, exist_ok=True)
    lock = {"lockfileVersion": 3, "packages": {"": {}}}
    for name, version in packages.items():
        lock["packages"][f"node_modules/{name}"] = {"version": version}
    (path / "package-lock.json").write_text(json.dumps(lock))
    if declared is not None:
        (path / "package.json").write_text(json.dumps({"dependencies": declared}))
    return path


def python_venv(path, packages):
    """Write a venv folder with ``{name: version}`` dist-info metadata."""
    path = pathlib.Path(path)
    (path / "pyvenv.cfg").parent.mkdir(parents=True, exist_ok=True)
    (path / "pyvenv.cfg").write_text("home = /usr/bin\n")
    site = path / "lib" / "python3.12" / "site-packages"
    for name, version in packages.items():
        info = site / f"{name.replace('-', '_')}-{version}.dist-info"
        info.mkdir(parents=True)
        (info / "METADATA").write_text(f"Metadata-Version: 2.3\nName: {name}\nVersion: {version}\n")
    return path


def fake_osv(advisories, summaries=None):
    """OSV stand-in. ``advisories`` maps package name -> list of advisory ids."""
    summaries = summaries or {}

    def fake(url, payload=None, timeout=20):
        if "querybatch" in url:
            return {
                "results": [
                    {"vulns": [{"id": a} for a in advisories.get(q["package"]["name"], [])]}
                    for q in payload["queries"]
                ]
            }
        aid = url.rsplit("/", 1)[-1]
        return {"id": aid, "summary": summaries.get(aid, f"Advisory {aid}")}

    return fake
