"""Threat Pulse: newest GitHub advisories, cross-referenced with local inventory."""

import io
import json
import unittest
import urllib.request
from unittest import mock

from helpers import fake_osv, isolate, mock_network, python_venv

from locdepintel import core


def ghsa(ident, name, kind="reviewed"):
    return {
        "ghsa_id": ident,
        "type": kind,
        "severity": "high",
        "summary": f"summary {ident}",
        "published_at": "2026-11-10T11:00:00Z",
        "vulnerabilities": [
            {"package": {"ecosystem": "pip", "name": name}, "vulnerable_version_range": "<9"}
        ],
    }


class ThreatPulseTests(unittest.TestCase):
    def setUp(self):
        self.base = isolate(self)
        python_venv(self.base / "p/.venv", {"urllib3": "2.2.2"})
        core.scan({"roots": [str(self.base)], "max_depth": 4})
        mock_network(self, fake_osv({"urllib3": ["GHSA-one"]}))
        core.assess()

    def feed(self, reviewed, malware=()):
        def urlopen(req, timeout):
            items = malware if "type=malware" in req.full_url else reviewed
            return io.BytesIO(json.dumps(list(items)).encode())

        return mock.patch.object(urllib.request, "urlopen", side_effect=urlopen)

    def test_local_status_requires_a_version_aware_match(self):
        with self.feed([ghsa("GHSA-one", "urllib3"), ghsa("GHSA-three", "urllib3")]):
            self.assertEqual(core.sync_pulse()["state"], "ok")
        status = {a["id"]: a["local_status"] for a in core.pulse()["advisories"]}
        self.assertEqual(status["GHSA-one"], "affected")  # OSV confirmed this version
        self.assertEqual(status["GHSA-three"], "package-present")  # name only, unconfirmed

    def test_unrelated_package_not_detected(self):
        with self.feed([ghsa("GHSA-x", "django")]):
            core.sync_pulse()
        self.assertEqual(core.pulse()["advisories"][0]["local_status"], "not-detected")

    def test_feed_failure_keeps_previous_advisories(self):
        with self.feed([ghsa("GHSA-one", "urllib3")]):
            core.sync_pulse()
        with mock.patch.object(urllib.request, "urlopen", side_effect=OSError("offline")):
            self.assertEqual(core.sync_pulse()["state"], "error")
        self.assertEqual(len(core.pulse()["advisories"]), 1)

    def test_malformed_feed_items_ignored(self):
        with self.feed([{"no": "id"}, "junk", ghsa("GHSA-ok", "six")]):
            result = core.sync_pulse()
        self.assertEqual(result["fetched"], 1)


if __name__ == "__main__":
    unittest.main()
