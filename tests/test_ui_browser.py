"""The dashboard, driven in a real headless browser against a real server.

Needs Playwright with Chromium (`pip install playwright && playwright install chromium`).
Skipped automatically when it is not installed; CI runs it in a separate job.
"""

import json
import threading
import unittest

from helpers import fake_osv, isolate, mock_network, npm_project

from locdepintel import core, server

try:
    from playwright.sync_api import sync_playwright

    with sync_playwright() as _pw:
        _pw.chromium.launch().close()
    HAVE_BROWSER = True
except Exception:  # not installed, or no browser binary
    HAVE_BROWSER = False

XSS_SUMMARY = '<img src=x onerror="window.__xss=1">Malicious release'
XSS_PACKAGE = "<svg onload=window.__xss=2>"


@unittest.skipUnless(HAVE_BROWSER, "Playwright + Chromium not installed")
class DashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._pw = sync_playwright().start()
        cls.browser = cls._pw.chromium.launch()

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls._pw.stop()

    def setUp(self):
        base = isolate(self)
        project = npm_project(
            base / "projects/shop", {"evil-pkg": "1.0.0", "left-pad": "1.3.0"}, {"evil-pkg": "^1"}
        )
        # A hostile lockfile can name a "package" anything; it must render as text.
        lock = json.loads((project / "package-lock.json").read_text())
        lock["packages"][f"node_modules/{XSS_PACKAGE}"] = {"version": "1.0.0"}
        (project / "package-lock.json").write_text(json.dumps(lock))
        core.save_config({"roots": [str(base / "projects")], "onboarding_complete": True})
        core.scan()
        mock_network(
            self,
            fake_osv(
                {"evil-pkg": ["MAL-2026-42"], XSS_PACKAGE: ["GHSA-xss"]},
                {"MAL-2026-42": XSS_SUMMARY, "GHSA-xss": XSS_SUMMARY},
            ),
        )
        core.assess()

        self.srv = server.make_server(port=0)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)
        self.context = self.browser.new_context()
        self.addCleanup(self.context.close)
        self.page = self.context.new_page()
        self.console_errors = []
        self.page.on(
            "console", lambda m: self.console_errors.append(m.text) if m.type == "error" else None
        )
        self.page.on("pageerror", lambda e: self.console_errors.append(str(e)))

    def open_dashboard(self):
        self.page.goto(self.srv.launch_url)
        self.page.wait_for_selector("#queue-body tr[data-queue]")

    def test_without_the_session_link_nothing_is_shown(self):
        base = self.srv.launch_url.split("/?")[0]
        self.page.goto(base + "/")
        self.assertIn("Session link required", self.page.inner_text("h1"))
        self.assertNotIn("evil-pkg", self.page.content())

    def test_overview_shows_findings_and_environments(self):
        self.open_dashboard()
        self.assertEqual(self.page.inner_text("#metric-affected"), "2")
        self.assertEqual(self.page.inner_text("#metric-envs"), "1")
        first_row = self.page.inner_text("#queue-body tr[data-queue] >> nth=0")
        self.assertIn("evil-pkg", first_row)  # malware first
        self.assertIn("npm (package-lock.json)", self.page.inner_text("#overview-envs"))
        self.assertEqual(self.console_errors, [])  # includes CSP violations

    def test_stat_tiles_navigate(self):
        self.open_dashboard()
        self.page.click("[data-stat=affected]")
        self.assertTrue(self.page.is_visible("#view-action"))
        self.page.click("[data-view=overview]")
        self.page.click("[data-stat=environments]")
        self.assertTrue(self.page.is_visible("#view-inventory"))

    def test_hostile_names_and_advisory_text_render_as_text(self):
        self.open_dashboard()
        self.page.click("[data-view=action]")
        self.page.locator("#action-body tr").filter(has_text="svg onload").first.click()
        drawer = self.page.inner_text("#drawer-body")
        self.assertIn(XSS_PACKAGE, drawer)  # shown literally...
        self.assertIn(XSS_SUMMARY, drawer)
        self.assertIsNone(self.page.evaluate("window.__xss"))  # ...and never executed
        self.assertEqual(self.page.locator("#drawer-body img, #drawer-body svg").count(), 0)

    def test_advisory_links_are_safe_and_remediation_is_offered(self):
        self.open_dashboard()
        self.page.click("[data-view=inventory]")
        self.page.locator("#inventory-body tr").filter(has_text="evil-pkg").first.click()
        if self.page.locator("[data-install]").count():
            self.page.locator("[data-install]").first.click()
        link = self.page.locator("#drawer-body a", has_text="original advisory").first
        self.assertEqual(link.get_attribute("href"), "https://osv.dev/vulnerability/MAL-2026-42")
        self.assertEqual(link.get_attribute("rel"), "noopener noreferrer")
        remedy = self.page.inner_text("#remedy")
        self.assertIn("npm explain 'evil-pkg'", remedy)
        self.assertTrue(self.page.is_visible("#copy-command"))

    def test_settings_saves_folders_through_the_ui(self):
        self.open_dashboard()
        self.page.click("#settings-button")
        self.page.fill("#roots", "/tmp/one\n/tmp/two")
        self.page.check("#include-global")
        self.page.click("#save-roots")
        self.page.wait_for_selector("#notice:not([hidden])")
        config = core.load_config()
        self.assertEqual(len(config["roots"]), 2)
        self.assertTrue(config["include_global"])


if __name__ == "__main__":
    unittest.main()
