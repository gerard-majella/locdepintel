import pathlib
import tempfile
import unittest
from unittest.mock import patch

from locdepintel import core


class VersionThreeTests(unittest.TestCase):
    def test_registry_intelligence_and_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            home = pathlib.Path(directory)
            with (
                patch.object(core, "home_data", return_value=home),
                patch.object(
                    core,
                    "request_json",
                    return_value={
                        "versions": [
                            {
                                "isDefault": True,
                                "versionKey": {"version": "2.1"},
                                "publishedAt": "2026-10-01T00:00:00Z",
                            },
                            {
                                "versionKey": {"version": "1.0"},
                                "publishedAt": "2025-01-01T00:00:00Z",
                            },
                        ]
                    },
                ) as mock,
            ):
                one = core.package_intelligence("PyPI", "example-demo-pkg")
                two = core.package_intelligence("PyPI", "example-demo-pkg")
                self.assertEqual(one["default_version"], "2.1")
                self.assertTrue(two["cached"])
                self.assertEqual(mock.call_count, 1)

    def test_invalid_package_rejected(self):
        with self.assertRaises(ValueError):
            core.package_intelligence("unknown", "thing")

    def test_ui_clickability_and_remediation(self):
        root = pathlib.Path(__file__).parents[1] / "locdepintel" / "static"
        html = (root / "index.html").read_text()
        js = (root / "app.js").read_text()
        for key in ("affected", "environments", "new"):
            self.assertIn('data-stat="' + key + '"', html)
        for token in (
            "package-intel",
            "data-reveal",
            "copy-command",
            "data-open-location",
            "version-lookup",
        ):
            self.assertIn(token, js)
        self.assertIn("scan-full", js)
        self.assertNotIn("eval(", js)


if __name__ == "__main__":
    unittest.main()
