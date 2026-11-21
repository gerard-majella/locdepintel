"""Local web UI and JSON API.

Security model
--------------
* Binds to 127.0.0.1 only.
* Every request needs the per-run secret token, either as the session cookie set by the
  launch link (``/?token=...``) or as ``Authorization: Bearer <token>``. This stops other
  local users and processes that do not have the token from reading the inventory or
  changing what gets scanned.
* ``Host`` must be ``127.0.0.1:<port>`` or ``localhost:<port>`` (DNS-rebinding protection).
* State-changing requests must be JSON, same-origin, and not ``Sec-Fetch-Site: cross-site``
  (CSRF protection that does not rely on the cookie alone).
"""

import hmac
import json
import pathlib
import secrets
import shutil
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import core

STATIC = pathlib.Path(__file__).parent / "static"
STATIC_FILES = {
    "/index.html": "text/html",
    "/app.js": "text/javascript",
    "/style.css": "text/css",
}
CSP = (
    "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; "
    "img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; "
    "form-action 'none'"
)
MAX_BODY = 20_000

UNAUTHORIZED_PAGE = b"""<!doctype html><meta charset="utf-8"><title>LocDepIntel</title>
<body style="font-family:sans-serif;max-width:36rem;margin:4rem auto;padding:0 1rem">
<h1>Session link required</h1>
<p>For your security, LocDepIntel only answers requests that carry the secret link printed
in the terminal when you ran <code>locdepintel serve</code>. Open that link, or restart the
server to get a new one.</p></body>"""

# One long-running task at a time (scan, check, pulse sync).
LOCK = threading.Lock()
JOB_LOCK = threading.Lock()
JOB = {
    "state": "idle",
    "stage": "Not started",
    "started": None,
    "ended": None,
    "result": None,
    "error": None,
}


def background_scan():
    """Run one discovery + exact-version advisory cycle in a thread, reporting real stages."""

    def worker():
        try:
            with JOB_LOCK:
                JOB.update(
                    state="running", stage="Discovering environments", started=core.timestamp()
                )
            discovered = core.scan()
            with JOB_LOCK:
                JOB["stage"] = "Checking exact versions against OSV"
            checked = core.assess()
            complete = checked.get("state") in ("ok", "no-packages") and not discovered.get(
                "warnings"
            )
            with JOB_LOCK:
                JOB.update(
                    state="complete" if complete else "partial",
                    stage="Scan finished",
                    ended=core.timestamp(),
                    result={"discovery": discovered, "security": checked},
                )
        except Exception as exc:
            with JOB_LOCK:
                JOB.update(
                    state="error", stage="Scan failed", ended=core.timestamp(), error=str(exc)[:500]
                )
        finally:
            LOCK.release()

    if not LOCK.acquire(blocking=False):
        return False
    with JOB_LOCK:
        JOB.update(
            state="starting",
            stage="Starting",
            started=core.timestamp(),
            ended=None,
            result=None,
            error=None,
        )
    threading.Thread(target=worker, daemon=True, name="locdepintel-fullscan").start()
    return True


def _valid_path_list(value, limit):
    return (
        isinstance(value, list)
        and len(value) <= limit
        and all(isinstance(x, str) and x and len(x) <= 1000 for x in value)
    )


class LocDepIntelServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port, token):
        super().__init__(("127.0.0.1", port), Handler)
        self.token = token
        bound = self.server_address[1]
        self.allowed_hosts = {f"127.0.0.1:{bound}", f"localhost:{bound}"}
        self.allowed_origins = {f"http://{h}" for h in self.allowed_hosts}
        # Browsers share cookies across ports on the same host, so include the port.
        self.cookie_name = f"ldi_session_{bound}"

    @property
    def launch_url(self):
        return f"http://127.0.0.1:{self.server_address[1]}/?token={self.token}"


def make_server(port=8765, token=None):
    """Create (but do not start) the server. ``port=0`` picks a free port."""
    if not isinstance(port, int) or not (port == 0 or 1024 <= port <= 65535):
        raise ValueError("Port must be 0 (any free port) or between 1024 and 65535")
    return LocDepIntelServer(port, token or secrets.token_urlsafe(32))


class Handler(BaseHTTPRequestHandler):
    server: LocDepIntelServer

    def log_message(self, fmt, *args):
        pass

    # ---------------------------------------------------------------- responses

    def _headers(self, code, content_type, length, extra=()):
        self.send_response(code)
        if content_type:
            self.send_header("Content-Type", content_type + "; charset=utf-8")
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", CSP)
        for name, value in extra:
            self.send_header(name, value)
        self.end_headers()

    def send(self, code, body, content_type="application/json"):
        payload = json.dumps(body).encode() if content_type == "application/json" else body
        self._headers(code, content_type, len(payload))
        self.wfile.write(payload)

    def send_unauthorized(self, path):
        if path.startswith("/api/"):
            return self.send(401, {"error": "Missing or invalid session token"})
        return self.send(401, UNAUTHORIZED_PAGE, "text/html")

    # ----------------------------------------------------------------- security

    def _cookie_token(self):
        for part in self.headers.get("Cookie", "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == self.server.cookie_name:
                return value
        return None

    def _bearer_token(self):
        scheme, _, value = self.headers.get("Authorization", "").partition(" ")
        return value.strip() if scheme.lower() == "bearer" else None

    def _token_ok(self, candidate):
        return bool(candidate) and hmac.compare_digest(
            candidate.encode(), self.server.token.encode()
        )

    def authenticated(self):
        return self._token_ok(self._cookie_token()) or self._token_ok(self._bearer_token())

    def host_ok(self):
        return self.headers.get("Host") in self.server.allowed_hosts

    def cross_site(self):
        origin = self.headers.get("Origin")
        if origin and origin not in self.server.allowed_origins:
            return True
        return self.headers.get("Sec-Fetch-Site", "same-origin") not in ("same-origin", "none")

    # -------------------------------------------------------------------- GET

    def do_GET(self):
        if not self.host_ok():
            return self.send(403, {"error": "Invalid host"})
        url = urlparse(self.path)
        path = url.path

        if path == "/" and "token" in parse_qs(url.query):
            supplied = parse_qs(url.query)["token"][0]
            if not self._token_ok(supplied):
                return self.send_unauthorized(path)
            cookie = (
                f"{self.server.cookie_name}={self.server.token}; "
                "HttpOnly; SameSite=Strict; Path=/"
            )
            self._headers(303, None, 0, [("Location", "/"), ("Set-Cookie", cookie)])
            return None

        if not self.authenticated():
            return self.send_unauthorized(path)

        routes = {
            "/api/state": core.state,
            "/api/overview": core.overview,
            "/api/onboarding": core.setup_status,
            "/api/inventory": core.inventory,
            "/api/grouped-findings": core.grouped_findings,
            "/api/pulse": core.pulse,
            "/api/export": core.export,
        }
        if path in routes:
            return self.send(200, routes[path]())
        if path == "/api/scan-status":
            with JOB_LOCK:
                return self.send(200, dict(JOB))

        if path == "/":
            path = "/index.html"
        if path not in STATIC_FILES:
            return self.send(404, {"error": "Not found"})
        return self.send(200, (STATIC / path[1:]).read_bytes(), STATIC_FILES[path])

    # ------------------------------------------------------------------- POST

    def do_POST(self):
        if not self.host_ok():
            return self.send(403, {"error": "Invalid host"})
        if not self.authenticated():
            return self.send_unauthorized(self.path)
        if self.cross_site():
            return self.send(403, {"error": "Cross-site request rejected"})
        content_type = self.headers.get("Content-Type", "").split(";")[0].strip().lower()
        if content_type != "application/json":
            return self.send(415, {"error": "Requests must be application/json"})
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return self.send(400, {"error": "Invalid Content-Length"})
        if length > MAX_BODY:
            return self.send(413, {"error": "Payload too large"})
        try:
            obj = json.loads(self.rfile.read(length)) if length else {}
        except ValueError:
            return self.send(400, {"error": "Invalid JSON"})
        if not isinstance(obj, dict):
            return self.send(400, {"error": "Expected a JSON object"})

        handler = {
            "/api/onboarding": self.post_onboarding,
            "/api/scan-full": self.post_scan_full,
            "/api/pulse-sync": lambda _o: self.locked(core.sync_pulse),
            "/api/scan": lambda _o: self.locked(core.scan),
            "/api/check": lambda _o: self.locked(core.assess),
            "/api/package-intel": self.post_package_intel,
            "/api/terminal": self.post_terminal,
            "/api/reveal": self.post_reveal,
            "/api/roots": self.post_roots,
        }.get(urlparse(self.path).path)
        if handler is None:
            return self.send(404, {"error": "Not found"})
        return handler(obj)

    def locked(self, func):
        if not LOCK.acquire(blocking=False):
            return self.send(409, {"error": "Another task is running"})
        try:
            return self.send(200, func())
        finally:
            LOCK.release()

    def post_onboarding(self, obj):
        roots = obj.get("roots")
        skip = obj.get("skip", False)
        if not isinstance(skip, bool) or (roots is not None and not _valid_path_list(roots, 15)):
            return self.send(400, {"error": "Invalid onboarding choices"})
        if not skip and not roots:
            return self.send(400, {"error": "Select at least one scan location"})
        return self.send(200, core.finish_onboarding(roots=roots, skip=skip))

    def post_scan_full(self, _obj):
        if not background_scan():
            return self.send(409, {"error": "Another scan is already running"})
        return self.send(202, {"state": "starting"})

    def post_roots(self, obj):
        roots = obj.get("roots")
        if not _valid_path_list(roots, 30):
            return self.send(400, {"error": "Invalid roots"})
        config = core.load_config()
        config["roots"] = [str(pathlib.Path(x).expanduser().resolve()) for x in roots]
        core.save_config(config)
        return self.send(200, {"ok": True, "roots": config["roots"]})

    def post_package_intel(self, obj):
        fields = [obj.get(k) for k in ("ecosystem", "name", "env", "version")]
        if not all(isinstance(x, str) and len(x) <= 2048 for x in fields):
            return self.send(400, {"error": "Invalid package selection"})
        ecosystem, name, env, version = fields
        with core.db() as con:
            known = con.execute(
                "SELECT 1 FROM inventory "
                "WHERE active=1 AND ecosystem=? AND name=? AND env=? AND version=?",
                (ecosystem, name, env, version),
            ).fetchone()
        if not known:
            return self.send(404, {"error": "Package not in discovered inventory"})
        try:
            return self.send(200, core.package_intelligence(ecosystem, name))
        except Exception as ex:
            return self.send(502, {"error": "Live registry metadata unavailable: " + str(ex)[:180]})

    def _known_env(self, obj):
        """Only paths the scanner itself recorded may be opened. Returns a Path or None."""
        requested = obj.get("path")
        if not isinstance(requested, str) or len(requested) > 2048:
            self.send(400, {"error": "Invalid location"})
            return None
        with core.db() as con:
            known = con.execute("SELECT 1 FROM envs WHERE path=?", (requested,)).fetchone()
        if not known:
            self.send(404, {"error": "Location was not discovered by LocDepIntel"})
            return None
        target = pathlib.Path(requested)
        if not target.exists():
            self.send(404, {"error": "Location no longer exists"})
            return None
        return target

    def post_terminal(self, obj):
        if sys.platform != "darwin":
            return self.send(
                501, {"error": "Opening Terminal is macOS only. Copy the path instead."}
            )
        target = self._known_env(obj)
        if target is None:
            return None
        if not target.is_dir():
            return self.send(404, {"error": "Environment directory unavailable"})
        # Static AppleScript; the path is passed as an argument, never interpolated.
        script = (
            "on run argv\n"
            ' tell application "Terminal" to do script "cd " & quoted form of (item 1 of argv)\n'
            ' activate application "Terminal"\n'
            "end run"
        )
        try:
            subprocess.Popen(
                ["/usr/bin/osascript", "-e", script, str(target)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError as ex:
            return self.send(500, {"error": "Unable to open Terminal: " + str(ex)})
        return self.send(200, {"ok": True})

    def post_reveal(self, obj):
        target = self._known_env(obj)
        if target is None:
            return None
        if sys.platform == "darwin":
            cmd = ["/usr/bin/open", "-R", str(target)]
        elif sys.platform == "win32":
            cmd = ["explorer.exe", str(target)]
        else:
            opener = shutil.which("xdg-open")
            if not opener:
                return self.send(501, {"error": "No file manager found; copy the location"})
            cmd = [opener, str(target if target.is_dir() else target.parent)]
        try:
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError as ex:
            return self.send(500, {"error": "Could not open location: " + str(ex)})
        return self.send(200, {"ok": True})
