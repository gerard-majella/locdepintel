"""Finding environments on disk, and the promise that scanning never runs scanned code."""

import json
import os
import pathlib
import sys
import unittest

from helpers import isolate, npm_project, python_venv

from locdepintel import core


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.base = isolate(self)
        self.root = self.base / "projects"
        python_venv(self.root / "api/.venv", {"example-pkg": "1.0"})
        npm_project(self.root / "web", {"left-pad": "1.3.0"})

    def test_finds_python_venv_and_npm_project(self):
        found, warnings = core.discover([self.root])
        self.assertFalse(warnings)
        labels = {pathlib.Path(p).name: label for p, label, _ in found}
        self.assertEqual(labels, {".venv": "Python venv", "web": "npm (package-lock.json)"})

    def test_same_root_listed_twice_is_scanned_once(self):
        found, _ = core.discover([self.root, str(self.root) + os.sep, self.root / "."])
        self.assertEqual(len(found), 2)

    def test_missing_root_reported_not_fatal(self):
        found, warnings = core.discover([self.root, self.base / "nope"])
        self.assertEqual(len(found), 2)
        self.assertIn("Root unavailable", warnings[0])

    def test_excluded_and_too_deep_folders_skipped(self):
        npm_project(self.root / "web/node_modules/nested-pkg", {"x": "1.0.0"})
        npm_project(self.root / "a/b/c/d/e/f/g/deep", {"y": "1.0.0"})
        found, _ = core.discover([self.root], max_depth=5)
        names = {pathlib.Path(p).name for p, _, _ in found}
        self.assertNotIn("nested-pkg", names)
        self.assertNotIn("deep", names)

    @unittest.skipIf(sys.platform == "win32", "POSIX symlinks")
    def test_symlinked_folders_not_followed(self):
        (self.root / "loop").symlink_to(self.root)
        found, _ = core.discover([self.root])
        self.assertEqual(len(found), 2)


class NoCodeExecutionTests(unittest.TestCase):
    """Scanned folders are hostile. Plant every common auto-run hook and prove none fires."""

    def setUp(self):
        self.base = isolate(self)
        self.marker = self.base / "PWNED"
        touch = f"open({str(self.marker)!r}, 'w').write('ran')\n"
        venv = python_venv(self.base / "proj/.venv", {"evil": "6.6.6"})
        site = venv / "lib/python3.12/site-packages"
        (site / "evil.py").write_text(touch)
        (site / "sitecustomize.py").write_text(touch)
        (site / "evil-autorun.pth").write_text(f"import os; {touch}")
        (site / "evil-6.6.6.dist-info/entry_points.txt").write_text("[console_scripts]\nx=evil:x\n")
        (self.base / "proj/setup.py").write_text(touch)
        (self.base / "proj/conftest.py").write_text(touch)
        bin_dir = venv / "bin"
        bin_dir.mkdir()
        fake_python = bin_dir / "python"
        fake_python.write_text(f"#!/bin/sh\ntouch {self.marker}\n")
        fake_python.chmod(0o755)
        project = npm_project(self.base / "proj/web", {"evil-npm": "1.0.0"})
        (project / "package.json").write_text(
            json.dumps({"scripts": {"preinstall": f"touch {self.marker}"}})
        )

    def test_scan_reads_metadata_only(self):
        result = core.scan({"roots": [str(self.base / "proj")], "max_depth": 6})
        self.assertEqual(result["packages"], 2)
        names = {p["name"] for p in core.inventory()}
        self.assertEqual(names, {"evil", "evil-npm"})
        self.assertFalse(self.marker.exists(), "scanning executed code from a scanned folder")


if __name__ == "__main__":
    unittest.main()
