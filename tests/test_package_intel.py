"""On-demand version lookups from deps.dev, with a 6 hour cache."""

import unittest

from helpers import isolate, mock_network

from locdepintel import core

DEPS_DEV = {
    "versions": [
        {
            "isDefault": True,
            "versionKey": {"version": "2.1"},
            "publishedAt": "2026-10-01T00:00:00Z",
        },
        {
            "versionKey": {"version": "1.0"},
            "publishedAt": "2025-01-01T00:00:00Z",
            "isDeprecated": True,
        },
    ]
}


class PackageIntelTests(unittest.TestCase):
    def setUp(self):
        isolate(self)

    def test_lookup_is_cached(self):
        fake = mock_network(self, lambda url, payload=None, timeout=20: DEPS_DEV)
        first = core.package_intelligence("PyPI", "example-demo-pkg")
        second = core.package_intelligence("PyPI", "example-demo-pkg")
        self.assertEqual(first["default_version"], "2.1")
        self.assertTrue(first["recent_versions"][1]["deprecated"])
        self.assertTrue(second["cached"])
        self.assertEqual(fake.call_count, 1)

    def test_unsupported_ecosystem_rejected(self):
        with self.assertRaises(ValueError):
            core.package_intelligence("unknown", "thing")


if __name__ == "__main__":
    unittest.main()
