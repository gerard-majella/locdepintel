"""Overview numbers and grouped findings, as shown on the dashboard."""

import unittest

from helpers import fake_osv, isolate, mock_network, python_venv

from locdepintel import core


class ReportingTests(unittest.TestCase):
    def setUp(self):
        self.base = isolate(self)
        for name in ("a", "b", "c"):
            python_venv(self.base / f"proj-{name}/.venv", {"urllib3": "2.2.2", "six": "1.16.0"})
        core.scan({"roots": [str(self.base)], "max_depth": 4})
        # urllib3 has two advisories; only one of them affects all three venvs equally
        mock_network(self, fake_osv({"urllib3": ["GHSA-one", "GHSA-two"]}))
        core.assess()

    def test_findings_grouped_by_package_version_across_installations(self):
        groups = core.grouped_findings()
        self.assertEqual(len(groups), 1)
        group = groups[0]
        self.assertEqual((group["name"], group["version"]), ("urllib3", "2.2.2"))
        self.assertEqual(group["advisory_count"], 2)
        self.assertEqual(group["installation_count"], 3)
        self.assertTrue(all(len(a["locations"]) == 3 for a in group["advisories"]))

    def test_overview_distinguishes_unique_packages_from_installations(self):
        stats = core.overview()["stats"]
        self.assertEqual(stats["affected_packages"], 1)
        self.assertEqual(stats["affected_installations"], 3)
        self.assertEqual(stats["installed_entries"], 6)
        self.assertEqual(stats["unique_packages"], 2)
        self.assertEqual(stats["environments"], 3)
        self.assertIsNone(stats["new_advisory_matches"])  # needs two successful checks

    def test_new_matches_counted_after_second_check(self):
        mock_network(self, fake_osv({"urllib3": ["GHSA-one", "GHSA-two"], "six": ["GHSA-new"]}))
        core.assess()
        self.assertEqual(core.overview()["stats"]["new_advisory_matches"], 1)

    def test_malware_sorted_before_vulnerabilities(self):
        mock_network(self, fake_osv({"urllib3": ["GHSA-one"], "six": ["MAL-2026-9"]}))
        core.assess()
        groups = core.grouped_findings()
        self.assertEqual([g["kind"] for g in groups], ["malware", "vulnerability"])

    def test_reading_the_overview_changes_nothing(self):
        def counts():
            with core.db() as con:
                return [
                    con.execute(f"SELECT count(*) FROM {t}").fetchone()[0]
                    for t in ("inventory", "findings", "events", "envs")
                ]

        before = counts()
        core.overview()
        core.state()
        core.grouped_findings()
        self.assertEqual(counts(), before)


if __name__ == "__main__":
    unittest.main()
