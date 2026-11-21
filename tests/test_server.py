"""Security tests for the local web server, run against a real server on a random free port."""

import http.client
import json
import pathlib
import tempfile
import threading
import unittest
from unittest import mock

from locdepintel import core, server


class ServerTestCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        data = pathlib.Path(tmp.name) / "data"
        data.mkdir()
        patcher = mock.patch.object(core, "home_data", lambda: data)
        patcher.start()
        self.addCleanup(patcher.stop)

        self.srv = server.make_server(port=0)  # 0 = let the OS pick a free port
        self.port = self.srv.server_address[1]
        self.token = self.srv.token
        thread = threading.Thread(target=self.srv.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)

    def request(self, method, path, body=None, headers=None, host=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        hdrs = {"Host": host or f"127.0.0.1:{self.port}"}
        hdrs.update(headers or {})
        conn.request(method, path, body=body, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp, data

    def cookie(self):
        return {"Cookie": f"{self.srv.cookie_name}={self.token}"}


class AuthenticationTests(ServerTestCase):
    def test_api_rejects_requests_without_token(self):
        for path in ("/api/state", "/api/export", "/api/inventory", "/"):
            resp, _ = self.request("GET", path)
            self.assertEqual(resp.status, 401, path)

    def test_post_without_token_cannot_change_scan_roots(self):
        resp, _ = self.request(
            "POST",
            "/api/roots",
            body=json.dumps({"roots": ["/"]}),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(resp.status, 401)
        self.assertNotEqual(core.load_config().get("roots"), ["/"])

    def test_wrong_token_rejected(self):
        resp, _ = self.request("GET", "/api/state", headers={"Cookie": f"{self.srv.cookie_name}=x"})
        self.assertEqual(resp.status, 401)
        resp, _ = self.request("GET", "/?token=wrong")
        self.assertEqual(resp.status, 401)

    def test_launch_link_sets_strict_httponly_cookie_and_redirects(self):
        resp, _ = self.request("GET", f"/?token={self.token}")
        self.assertEqual(resp.status, 303)
        self.assertEqual(resp.getheader("Location"), "/")
        cookie = resp.getheader("Set-Cookie")
        self.assertIn(f"{self.srv.cookie_name}={self.token}", cookie)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        self.assertEqual(resp.getheader("Referrer-Policy"), "no-referrer")

    def test_cookie_or_bearer_token_grants_access(self):
        resp, _ = self.request("GET", "/api/state", headers=self.cookie())
        self.assertEqual(resp.status, 200)
        resp, _ = self.request(
            "GET", "/api/state", headers={"Authorization": f"Bearer {self.token}"}
        )
        self.assertEqual(resp.status, 200)

    def test_each_server_gets_a_fresh_random_token(self):
        other = server.make_server(port=0)
        self.addCleanup(other.server_close)
        self.assertNotEqual(other.token, self.token)
        self.assertGreaterEqual(len(self.token), 40)


class RequestForgeryTests(ServerTestCase):
    def test_dns_rebinding_host_rejected_even_with_token(self):
        resp, _ = self.request("GET", "/api/state", headers=self.cookie(), host="evil.example")
        self.assertEqual(resp.status, 403)

    def test_cross_origin_post_rejected_even_with_cookie(self):
        headers = dict(self.cookie(), **{"Content-Type": "application/json"})
        headers["Origin"] = "https://evil.example"
        resp, _ = self.request("POST", "/api/roots", body='{"roots":["/"]}', headers=headers)
        self.assertEqual(resp.status, 403)

    def test_cross_site_fetch_metadata_rejected(self):
        headers = dict(self.cookie(), **{"Content-Type": "application/json"})
        headers["Sec-Fetch-Site"] = "cross-site"
        resp, _ = self.request("POST", "/api/roots", body='{"roots":["/"]}', headers=headers)
        self.assertEqual(resp.status, 403)

    def test_post_requires_json_content_type(self):
        # HTML forms can only send text/plain, urlencoded or multipart without a CORS preflight.
        headers = dict(self.cookie(), **{"Content-Type": "text/plain"})
        resp, _ = self.request("POST", "/api/roots", body='{"roots":["/"]}', headers=headers)
        self.assertEqual(resp.status, 415)

    def test_same_origin_post_accepted(self):
        root = tempfile.mkdtemp()
        headers = dict(self.cookie(), **{"Content-Type": "application/json"})
        headers["Origin"] = f"http://127.0.0.1:{self.port}"
        resp, data = self.request(
            "POST", "/api/roots", body=json.dumps({"roots": [root]}), headers=headers
        )
        self.assertEqual(resp.status, 200, data)


class SettingsTests(ServerTestCase):
    def post(self, body):
        headers = dict(self.cookie(), **{"Content-Type": "application/json"})
        return self.request("POST", "/api/roots", body=json.dumps(body), headers=headers)

    def test_include_global_toggle_saved(self):
        resp, _ = self.post({"roots": [tempfile.mkdtemp()], "include_global": True})
        self.assertEqual(resp.status, 200)
        self.assertTrue(core.load_config()["include_global"])

    def test_include_global_must_be_boolean(self):
        resp, _ = self.post({"roots": [tempfile.mkdtemp()], "include_global": "yes"})
        self.assertEqual(resp.status, 400)


class PortTests(ServerTestCase):
    def test_host_allow_list_follows_the_actual_port(self):
        self.assertNotEqual(self.port, 8765)
        resp, _ = self.request("GET", "/api/state", headers=self.cookie())
        self.assertEqual(resp.status, 200)
        resp, _ = self.request(
            "GET", "/api/state", headers=self.cookie(), host=f"localhost:{self.port}"
        )
        self.assertEqual(resp.status, 200)
        resp, _ = self.request("GET", "/api/state", headers=self.cookie(), host="127.0.0.1:8765")
        self.assertEqual(resp.status, 403)

    def test_cookie_name_is_port_specific(self):
        # Cookies ignore ports, so two instances must not overwrite each other's session.
        self.assertIn(str(self.port), self.srv.cookie_name)

    def test_privileged_or_invalid_ports_rejected(self):
        for bad in (80, 70000, -1):
            with self.assertRaises(ValueError):
                server.make_server(port=bad)


if __name__ == "__main__":
    unittest.main()
