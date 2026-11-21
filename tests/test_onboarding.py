"""First-run welcome flow and folder suggestions."""

import pathlib
import unittest
from unittest import mock

from helpers import isolate

from locdepintel import core


class OnboardingTests(unittest.TestCase):
    def setUp(self):
        self.base = isolate(self)

    def test_fresh_install_shows_welcome_and_skip_persists(self):
        self.assertFalse(core.setup_status()["complete"])
        core.finish_onboarding(skip=True)
        self.assertTrue(core.setup_status()["complete"])
        self.assertTrue(core.load_config()["onboarding_skipped"])

    def test_existing_scan_history_skips_welcome(self):
        with core.db() as con:
            con.execute("INSERT INTO scans(started,status,packages) VALUES ('t','ok',0)")
        status = core.setup_status()
        self.assertTrue(status["complete"])
        self.assertTrue(status["existing_user"])

    def test_chosen_folders_saved_as_absolute_paths(self):
        folder = self.base / "Documents"
        folder.mkdir()
        core.finish_onboarding(roots=[str(folder)], skip=False)
        self.assertEqual(core.load_config()["roots"], [str(folder.resolve())])

    def test_environment_folder_labels(self):
        with mock.patch("pathlib.Path.home", return_value=pathlib.Path("/Users/dev")):
            label = core.environment_folder
            self.assertEqual(label("/Users/dev/Documents/p/.venv"), "Documents")
            self.assertEqual(label("/Users/dev/.local/pipx/venvs/x"), "Hidden locations")
            self.assertEqual(label("/opt/other"), "Other locations")


if __name__ == "__main__":
    unittest.main()
