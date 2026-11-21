"""Inventory must reflect the current scan scope: no stale packages, no stale alerts."""

import json
import pathlib
import shutil
import tempfile
import unittest
from unittest import mock

from locdepintel import core


def npm_project(path, packages):
    path.mkdir(parents=True)
    lock = {"lockfileVersion": 3, "packages": {"": {}}}
    for name, version in packages.items():
        lock["packages"][f"node_modules/{name}"] = {"version": version}
    (path / "package-lock.json").write_text(json.dumps(lock))


def fake_osv_flagging(bad_name):
    def fake(url, payload=None, timeout=20):
        if "querybatch" in url:
            return {
                "results": [
                    {"vulns": [{"id": "MAL-2026-1"}]} if q["package"]["name"] == bad_name else {}
                    for q in payload["queries"]
                ]
            }
        return {"id": "MAL-2026-1", "summary": "malicious"}

    return fake


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = pathlib.Path(tmp.name)
        data = self.base / "data"
        data.mkdir()
        patcher = mock.patch.object(core, "home_data", lambda: data)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.root_a = self.base / "a"
        self.root_b = self.base / "b"
        npm_project(self.root_a / "app1", {"evil-pkg": "1.0.0"})
        npm_project(self.root_b / "app2", {"left-pad": "1.3.0"})

    def config(self, *roots):
        return {"roots": [str(r) for r in roots], "max_depth": 5, "max_dirs": 1000}

    def active_names(self):
        return {p["name"] for p in core.inventory()}

    def active_findings(self):
        return core.state()["findings"]

    def env_states(self):
        with core.db() as con:
            return {r["path"]: r["state"] for r in con.execute("SELECT path,state FROM envs")}

    def test_removing_a_root_retires_its_packages_findings_and_envs(self):
        core.scan(self.config(self.root_a, self.root_b))
        with mock.patch.object(core, "request_json", side_effect=fake_osv_flagging("evil-pkg")):
            core.assess()
        self.assertEqual(len(self.active_findings()), 1)

        result = core.scan(self.config(self.root_b))  # user drops root A from settings

        self.assertEqual(self.active_names(), {"left-pad"})
        self.assertEqual(self.active_findings(), [], "alert for an unmonitored folder persisted")
        self.assertEqual(self.env_states()[str(self.root_a / "app1")], "out-of-scope")
        self.assertEqual(core.state()["stats"]["environments"], 1)
        self.assertEqual(result["out_of_scope"], 1)

    def test_one_missing_root_does_not_block_cleanup_in_other_roots(self):
        core.scan(self.config(self.root_a, self.root_b))
        shutil.rmtree(self.root_b / "app2")  # project deleted in a healthy root
        missing = self.base / "unplugged-drive"

        result = core.scan(self.config(self.root_a, self.root_b, missing))

        self.assertIn("Root unavailable", " ".join(result["warnings"]))
        self.assertEqual(self.active_names(), {"evil-pkg"})
        self.assertEqual(self.env_states()[str(self.root_b / "app2")], "missing")
        self.assertEqual(result["removed"], 1)

    def test_unavailable_root_keeps_its_last_known_inventory(self):
        core.scan(self.config(self.root_a, self.root_b))
        moved = self.base / "moved"
        self.root_b.rename(moved)  # e.g. external drive unplugged; root still configured

        result = core.scan(self.config(self.root_a, self.root_b))

        self.assertEqual(self.active_names(), {"evil-pkg", "left-pad"})
        self.assertEqual(result["removed"], 0)
        self.assertEqual(self.env_states()[str(self.root_b / "app2")], "monitored")

    def test_directory_cap_only_protects_roots_not_fully_walked(self):
        core.scan(self.config(self.root_a, self.root_b))
        shutil.rmtree(self.root_a / "app1")
        cfg = self.config(self.root_a, self.root_b)
        cfg["max_dirs"] = 2  # root A finishes (2 dirs), root B is cut off
        result = core.scan(cfg)
        self.assertIn("Directory cap", " ".join(result["warnings"]))
        self.assertEqual(self.active_names(), {"left-pad"})

    def test_removed_count_matches_what_was_actually_removed(self):
        core.scan(self.config(self.root_a, self.root_b))
        result = core.scan(self.config(self.root_a, self.root_b))
        self.assertEqual(result["removed"], 0)
        self.assertEqual(result["added"], 0)

    def test_root_re_added_reactivates_packages(self):
        core.scan(self.config(self.root_a, self.root_b))
        core.scan(self.config(self.root_b))
        core.scan(self.config(self.root_a, self.root_b))
        self.assertEqual(self.active_names(), {"evil-pkg", "left-pad"})
        self.assertEqual(self.env_states()[str(self.root_a / "app1")], "monitored")


if __name__ == "__main__":
    unittest.main()
