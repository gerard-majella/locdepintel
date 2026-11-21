import pathlib
import tempfile
import unittest
from unittest.mock import patch

from locdepintel import core


class V07Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = pathlib.Path(self.tmp.name)
        self.patcher = patch.object(core, "home_data", lambda: self.base)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def test_first_run_and_skip_persists(self):
        before = core.setup_status()
        self.assertFalse(before["complete"])
        core.finish_onboarding(skip=True)
        self.assertTrue(core.setup_status()["complete"])
        self.assertTrue(core.load_config()["onboarding_skipped"])

    def test_existing_user_bypasses_welcome(self):
        with core.db() as db:
            db.execute("INSERT INTO scans(started,status,packages) VALUES ('t','ok',0)")
        self.assertTrue(core.setup_status()["complete"])
        self.assertTrue(core.setup_status()["existing_user"])

    def test_roots_are_persisted(self):
        d = self.base / "Documents"
        d.mkdir()
        core.finish_onboarding(roots=[str(d)], skip=False)
        self.assertEqual(core.load_config()["roots"], [str(d.resolve())])

    def test_scans_same_root_only_once(self):
        env = self.base / "x" / "demo" / ".venv"
        (env / "lib" / "python3.12" / "site-packages" / "foo-1.0.dist-info").mkdir(parents=True)
        (env / "pyvenv.cfg").write_text("home = /tmp")
        (
            env / "lib" / "python3.12" / "site-packages" / "foo-1.0.dist-info" / "METADATA"
        ).write_text("Name: foo\nVersion: 1.0\n")
        found, warnings = core.discover([str(self.base / "x"), str(self.base / "x")], max_depth=6)
        self.assertEqual(len(found), 1)
        self.assertFalse(warnings)
        self.assertEqual(found[0][2][0][:3], ("PyPI", "foo", "1.0"))

    def test_folder_classification(self):
        with patch("pathlib.Path.home", return_value=pathlib.Path("/Users/developer")):
            self.assertEqual(
                core.environment_folder("/Users/developer/Documents/project/.venv"), "Documents"
            )
            self.assertEqual(
                core.environment_folder("/Users/developer/Desktop/work/.venv"), "Desktop"
            )
            self.assertEqual(core.environment_folder("/opt/other"), "Other locations")


if __name__ == "__main__":
    unittest.main()
