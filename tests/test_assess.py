"""Advisory checking against OSV (network mocked)."""

import json
import pathlib
import tempfile
import threading
import time
import unittest
from unittest import mock

from locdepintel import core


class AssessTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = pathlib.Path(tmp.name)
        data = base / "data"
        data.mkdir()
        patcher = mock.patch.object(core, "home_data", lambda: data)
        patcher.start()
        self.addCleanup(patcher.stop)
        project = base / "proj"
        project.mkdir()
        lock = {"lockfileVersion": 3, "packages": {"": {}}}
        for i in range(4):
            lock["packages"][f"node_modules/pkg{i}"] = {"version": "1.0.0"}
        (project / "package-lock.json").write_text(json.dumps(lock))
        core.scan({"roots": [str(base)], "max_depth": 5, "max_dirs": 100})

    def fake_osv(self, advisories_per_pkg, delay=0.0):
        """pkg0 gets advisories_per_pkg[0] advisories, and so on."""
        lock = threading.Lock()
        self.in_flight = self.max_in_flight = 0

        def fake(url, payload=None, timeout=20):
            if "querybatch" in url:
                results = []
                for q in payload["queries"]:
                    i = int(q["package"]["name"][3:])
                    ids = [f"GHSA-{i}-{n}" for n in range(advisories_per_pkg[i])]
                    results.append({"vulns": [{"id": x} for x in ids]})
                return {"results": results}
            with lock:
                self.in_flight += 1
                self.max_in_flight = max(self.max_in_flight, self.in_flight)
            time.sleep(delay)
            with lock:
                self.in_flight -= 1
            return {"id": url.rsplit("/", 1)[-1], "summary": "test advisory"}

        return fake

    def test_advisory_count_is_total_unique_not_last_package(self):
        with mock.patch.object(core, "request_json", side_effect=self.fake_osv([3, 0, 0, 1])):
            result = core.assess()
        self.assertEqual(result["advisories"], 4)
        self.assertIn("4 unique OSV advisories", core.state()["checks"][0]["note"])

    def test_advisory_details_fetched_in_parallel(self):
        per_pkg = [10, 10, 10, 10]  # 40 advisories x 0.1 s = 4 s if sequential
        with mock.patch.object(core, "request_json", side_effect=self.fake_osv(per_pkg, 0.1)):
            started = time.monotonic()
            result = core.assess()
            elapsed = time.monotonic() - started
        self.assertEqual(result["state"], "ok")
        self.assertEqual(result["advisories"], 40)
        self.assertGreater(self.max_in_flight, 1)
        self.assertLessEqual(self.max_in_flight, core.OSV_DETAIL_WORKERS)  # polite to OSV
        self.assertLess(elapsed, 2.0)

    def test_one_failed_detail_fetch_does_not_fail_the_check(self):
        base = self.fake_osv([2, 0, 0, 0])

        def flaky(url, payload=None, timeout=20):
            if url.endswith("GHSA-0-1"):
                raise OSError("timeout")
            return base(url, payload, timeout)

        with mock.patch.object(core, "request_json", side_effect=flaky):
            result = core.assess()
        self.assertEqual(result["state"], "ok")
        self.assertEqual(len(core.state()["findings"]), 2)


if __name__ == "__main__":
    unittest.main()
