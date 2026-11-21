import json
import pathlib
import tempfile
import unittest
import unittest.mock

from locdepintel import core


class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = pathlib.Path(self.tmp.name)
        self.patch = unittest.mock.patch.object(
            core, "home_data", lambda: self.home / "application"
        )
        self.patch.start()
        self.addCleanup(self.patch.stop)
        (self.home / "application").mkdir()
        self.root = self.home / "projects"
        self.root.mkdir()
        self.py = self.root / "test-python"
        self.py.mkdir()
        (self.py / "pyvenv.cfg").write_text("home = /usr/bin")
        d = self.py / "lib" / "python3.13" / "site-packages" / "example_pkg-1.0.dist-info"
        d.mkdir(parents=True)
        (d / "METADATA").write_text("Metadata-Version: 2.3\nName: example-pkg\nVersion: 1.0\n")
        self.js = self.root / "test-npm"
        self.js.mkdir()
        (self.js / "package-lock.json").write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {"": {}, "node_modules/left-pad": {"version": "1.3.0"}},
                }
            )
        )
        self.c = {
            "roots": [str(self.root)],
            "max_depth": 5,
            "max_dirs": 1000,
            "include_global": False,
        }

    def test_discover_both(self):
        env, issues = core.discover([self.root])
        self.assertEqual(len(env), 2)
        self.assertFalse(issues)
        self.assertEqual({e[1] for e in env}, {"npm", "Python"})

    def test_scan_history(self):
        r = core.scan(self.c)
        self.assertEqual(r["packages"], 2)
        self.assertEqual(r["added"], 2)
        r2 = core.scan(self.c)
        self.assertEqual(r2["added"], 0)
        self.assertEqual(len(core.inventory()), 2)
        (self.js / "package-lock.json").write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {"": {}, "node_modules/left-pad": {"version": "1.4.0"}},
                }
            )
        )
        r3 = core.scan(self.c)
        self.assertEqual(r3["added"], 1)
        self.assertEqual(r3["removed"], 1)
        self.assertEqual(core.state()["stats"]["packages"], 2)

    def test_malware_from_live_schema(self):
        core.scan(self.c)

        def fake(url, payload=None, timeout=20):
            if "querybatch" in url:
                return {
                    "results": [
                        (
                            {"vulns": [{"id": "MAL-2026-123"}]}
                            if q["package"]["ecosystem"] == "npm"
                            else {"vulns": []}
                        )
                        for q in payload["queries"]
                    ]
                }
            return {"id": "MAL-2026-123", "summary": "Test malicious release"}

        with unittest.mock.patch.object(core, "request_json", side_effect=fake):
            res = core.assess()
        self.assertEqual(res["state"], "ok")
        self.assertEqual(core.state()["stats"]["malware"], 1)
        with unittest.mock.patch.object(core, "request_json", side_effect=OSError("offline")):
            self.assertEqual(core.assess()["state"], "error")
        self.assertEqual(core.state()["stats"]["malware"], 1)  # offline must never silently clear

    def test_no_untrusted_code_execution(self):
        records = core.python_env(self.py)
        self.assertEqual(records, [("PyPI", "example-pkg", "1.0", "unknown")])

    def test_missing_root_is_partial(self):
        core.scan(self.c)
        # Keeping the original root and adding an unavailable one: partial, nothing lost.
        r = core.scan(dict(self.c, roots=[str(self.root), str(self.root / "nonexistent")]))
        self.assertTrue(r["warnings"])
        self.assertEqual(core.state()["stats"]["packages"], 2)
        # Replacing the root entirely: old packages are out of scope, not silently kept.
        r = core.scan(dict(self.c, roots=[str(self.root / "nonexistent")]))
        self.assertTrue(r["warnings"])
        self.assertEqual(r["out_of_scope"], 2)
        self.assertEqual(core.state()["stats"]["packages"], 0)


if __name__ == "__main__":
    unittest.main()
