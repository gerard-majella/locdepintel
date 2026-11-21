"""Schema versioning: fresh installs, upgrades from DepWatch 0.7 databases, failures."""

import pathlib
import sqlite3
import tempfile
import unittest
from unittest import mock

from locdepintel import core

# Exactly what DepWatch 0.7 created (no user_version, no advisory cache).
LEGACY_07_SCHEMA = """
CREATE TABLE scans(id INTEGER PRIMARY KEY, started TEXT, ended TEXT, status TEXT, error TEXT,
  packages INTEGER DEFAULT 0, checked INTEGER DEFAULT 0);
CREATE TABLE inventory(env TEXT NOT NULL, ecosystem TEXT NOT NULL, name TEXT NOT NULL,
  version TEXT NOT NULL, direct TEXT, discovered TEXT NOT NULL, seen TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1, PRIMARY KEY(env,ecosystem,name,version));
CREATE TABLE findings(id INTEGER PRIMARY KEY, env TEXT, ecosystem TEXT, name TEXT, version TEXT,
  advisory TEXT, kind TEXT, summary TEXT, url TEXT, first_seen TEXT, last_seen TEXT,
  active INTEGER DEFAULT 1, UNIQUE(env,ecosystem,name,version,advisory));
INSERT INTO inventory VALUES('/p','npm','left-pad','1.3.0','direct','2026-01-01','2026-01-01',1);
INSERT INTO findings(env,ecosystem,name,version,advisory,kind,active)
  VALUES('/p','npm','left-pad','1.3.0','MAL-1','malware',1);
"""


class MigrationTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.data = pathlib.Path(tmp.name)
        patcher = mock.patch.object(core, "home_data", lambda: self.data)
        patcher.start()
        self.addCleanup(patcher.stop)
        core._MIGRATED.clear()
        self.addCleanup(core._MIGRATED.clear)

    def raw(self):
        return sqlite3.connect(core.db_path())

    def version(self):
        with self.raw() as con:
            return con.execute("PRAGMA user_version").fetchone()[0]

    def tables(self):
        with self.raw() as con:
            return {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}

    def test_fresh_database_gets_latest_schema(self):
        with core.db():
            pass
        self.assertEqual(self.version(), core.SCHEMA_VERSION)
        self.assertTrue({"inventory", "findings", "envs", "advisory_cache"} <= self.tables())

    def test_upgrade_from_depwatch_07_keeps_data(self):
        with self.raw() as con:
            con.executescript(LEGACY_07_SCHEMA)
        self.assertEqual(self.version(), 0)
        self.assertEqual(core.state()["stats"]["malware"], 1)  # opening it migrates it
        self.assertEqual(self.version(), core.SCHEMA_VERSION)
        self.assertEqual([p["name"] for p in core.inventory()], ["left-pad"])
        self.assertIn("advisory_cache", self.tables())

    def test_database_from_newer_release_is_refused(self):
        with self.raw() as con:
            con.execute(f"PRAGMA user_version={core.SCHEMA_VERSION + 1}")
        with self.assertRaisesRegex(RuntimeError, "newer version of LocDepIntel"):
            with core.db():
                pass

    def test_failed_migration_rolls_back_completely(self):
        broken = core.MIGRATIONS + [
            (core.SCHEMA_VERSION + 1, "CREATE TABLE half_done(x); THIS IS NOT SQL;")
        ]
        with (
            mock.patch.object(core, "MIGRATIONS", broken),
            mock.patch.object(core, "SCHEMA_VERSION", core.SCHEMA_VERSION + 1),
        ):
            with self.assertRaises(sqlite3.Error):
                with core.db():
                    pass
        self.assertEqual(self.version(), core.SCHEMA_VERSION)  # earlier steps did commit
        self.assertNotIn("half_done", self.tables())  # the failed step left nothing behind

    def test_schema_work_runs_once_per_process(self):
        with mock.patch.object(core, "_migrate", wraps=core._migrate) as spy:
            for _ in range(5):
                with core.db():
                    pass
        self.assertEqual(spy.call_count, 1)


class ConcurrentMigrationTests(unittest.TestCase):
    def test_many_processes_opening_a_new_database_at_once(self):
        """The web UI and a scheduled scan may start together; both must succeed."""
        import os
        import subprocess
        import sys

        data = tempfile.mkdtemp()
        root = pathlib.Path(__file__).resolve().parents[1]
        code = (
            "import sys, pathlib; from locdepintel import core;"
            f"core.home_data = lambda: pathlib.Path({data!r});"
            "print(core.state()['stats']['packages'])"
        )
        procs = [
            subprocess.Popen(
                [sys.executable, "-c", code],
                cwd=root,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=dict(os.environ),
            )
            for _ in range(8)
        ]
        results = [p.communicate(timeout=60) for p in procs]
        for (out, err), proc in zip(results, procs, strict=True):
            self.assertEqual(proc.returncode, 0, err)
            self.assertEqual(out.strip(), "0")
        with sqlite3.connect(pathlib.Path(data) / "locdepintel.sqlite3") as con:
            self.assertEqual(con.execute("PRAGMA user_version").fetchone()[0], core.SCHEMA_VERSION)


class AdvisoryCacheTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        data = pathlib.Path(tmp.name)
        patcher = mock.patch.object(core, "home_data", lambda: data)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_details_cached_for_a_day(self):
        calls = []

        def fake(url, payload=None, timeout=20):
            calls.append(url)
            return {"id": url.rsplit("/", 1)[-1], "summary": "s"}

        with mock.patch.object(core, "request_json", side_effect=fake):
            first = core.fetch_advisory_details({"GHSA-a", "GHSA-b"})
            second = core.fetch_advisory_details({"GHSA-a", "GHSA-b", "GHSA-c"})
        self.assertEqual(first["GHSA-a"]["summary"], "s")
        self.assertEqual(second["GHSA-c"]["id"], "GHSA-c")
        self.assertEqual(len(calls), 3)  # a, b, then only c

    def test_failed_downloads_are_not_cached(self):
        with mock.patch.object(core, "request_json", side_effect=OSError("down")):
            core.fetch_advisory_details({"GHSA-x"})
        with mock.patch.object(core, "request_json", return_value={"id": "GHSA-x"}) as ok:
            core.fetch_advisory_details({"GHSA-x"})
        self.assertEqual(ok.call_count, 1)


if __name__ == "__main__":
    unittest.main()
