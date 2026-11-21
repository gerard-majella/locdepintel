import json
import tempfile
import unittest
from pathlib import Path

from locdepintel import core


class UpgradeTests(unittest.TestCase):
    def test_npm_origin_from_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            (p / "package.json").write_text(json.dumps({"dependencies": {"top-dep": "^1.0"}}))
            (p / "package-lock.json").write_text(
                json.dumps(
                    {
                        "lockfileVersion": 3,
                        "packages": {
                            "": {},
                            "node_modules/top-dep": {"version": "1.0"},
                            "node_modules/child-dep": {"version": "2.0"},
                        },
                    }
                )
            )
            data = {x[1]: x[3] for x in core.npm_lock(p)}
            self.assertEqual(data["top-dep"], "direct")
            self.assertEqual(data["child-dep"], "transitive")

    def test_no_install_commands_in_ui(self):
        js = (Path(__file__).resolve().parents[1] / "locdepintel" / "static" / "app.js").read_text()
        self.assertIn("inv-eco", js)
        self.assertIn("data-reveal", js)
        self.assertNotIn("eval(", js)


class WorkspaceTests(unittest.TestCase):
    def test_npm_workspace_members_are_not_sent_as_public_packages(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            (p / "package.json").write_text(
                json.dumps({"workspaces": ["packages/*"], "dependencies": {"lodash": "^4"}})
            )
            (p / "package-lock.json").write_text(
                json.dumps(
                    {
                        "lockfileVersion": 3,
                        "packages": {
                            "": {},
                            "packages/internal-app": {"version": "0.0.1"},
                            "node_modules/internal-app": {
                                "resolved": "packages/internal-app",
                                "link": True,
                            },
                            "node_modules/lodash": {"version": "4.17.20"},
                        },
                    }
                )
            )
            names = {x[1] for x in core.npm_lock(p)}
            self.assertEqual(names, {"lodash"})
