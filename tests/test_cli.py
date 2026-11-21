"""Run the real command line in a subprocess, the way a user does."""

import errno
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run_cli(*args, home, timeout=20):
    env = dict(os.environ, HOME=home, XDG_DATA_HOME=os.path.join(home, "data"))
    env["LOCALAPPDATA"] = os.path.join(home, "data")
    return subprocess.run(
        [sys.executable, "-m", "locdepintel", *args],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


class CliTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = tmp.name

    def test_old_python_gets_a_clear_message_not_a_traceback(self):
        code = (
            "import sys, runpy; sys.version_info = (3, 9, 6, 'final', 0);"
            "sys.argv = ['locdepintel', 'serve'];"
            "runpy.run_module('locdepintel', run_name='__main__')"
        )
        out = subprocess.run(
            [sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, timeout=20
        )
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("needs Python 3.11 or newer, but this is Python 3.9.6", out.stderr)
        self.assertNotIn("Traceback", out.stderr)

    def test_closed_pipe_detection_per_platform(self):
        from unittest import mock

        from locdepintel import __main__ as cli

        einval = OSError(errno.EINVAL, "Invalid argument")
        self.assertTrue(cli._closed_pipe(BrokenPipeError()))
        with mock.patch.object(sys, "platform", "win32"):
            self.assertTrue(cli._closed_pipe(einval))
        with mock.patch.object(sys, "platform", "linux"):
            self.assertFalse(cli._closed_pipe(einval))  # a real error elsewhere: re-raise
        self.assertFalse(cli._closed_pipe(OSError(errno.ENOSPC, "No space left")))

    def test_help_lists_commands(self):
        out = run_cli("--help", home=self.home)
        self.assertEqual(out.returncode, 0, out.stderr)
        for cmd in ("serve", "scan", "schedule", "alerts"):
            self.assertIn(cmd, out.stdout)

    def test_offline_scan_runs(self):
        project = Path(self.home) / "proj"
        project.mkdir()
        (project / "package-lock.json").write_text(
            '{"lockfileVersion":3,"packages":{"":{},"node_modules/a":{"version":"1.0.0"}}}'
        )
        self.assertEqual(run_cli("roots", str(project), home=self.home).returncode, 0)
        out = run_cli("scan", "--offline", home=self.home)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn('"packages": 1', out.stdout)

    def test_globals_toggle(self):
        self.assertIn("off", run_cli("globals", home=self.home).stdout)
        self.assertIn("on", run_cli("globals", "on", home=self.home).stdout)
        self.assertIn("Global installs: on", run_cli("globals", home=self.home).stdout)

    def test_output_piped_into_a_closed_reader_does_not_traceback(self):
        """`locdepintel inventory | head -1` must not end with a BrokenPipeError traceback."""
        project = Path(self.home) / "big"
        project.mkdir()
        packages = {f"node_modules/pkg-{i}": {"version": "1.0.0"} for i in range(3000)}
        (project / "package-lock.json").write_text(
            json.dumps({"lockfileVersion": 3, "packages": {"": {}, **packages}})
        )
        run_cli("roots", str(project), home=self.home)
        run_cli("scan", "--offline", home=self.home)
        env = dict(os.environ, HOME=self.home, XDG_DATA_HOME=os.path.join(self.home, "data"))
        env["LOCALAPPDATA"] = os.path.join(self.home, "data")
        proc = subprocess.Popen(
            [sys.executable, "-m", "locdepintel", "inventory"],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        proc.stdout.readline()
        proc.stdout.close()  # reader goes away after one line, like `| head -1`
        err = proc.stderr.read()
        proc.stderr.close()
        proc.wait(timeout=30)
        self.assertNotIn(b"Traceback", err)
        self.assertNotIn(b"BrokenPipeError", err)

    def test_serve_rejects_bad_port_with_message(self):
        out = run_cli("serve", "--port", "80", "--no-browser", home=self.home)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("Port must be", out.stderr)
        self.assertNotIn("Traceback", out.stderr)

    def test_serve_prints_link_and_enforces_token(self):
        env = dict(os.environ, HOME=self.home, XDG_DATA_HOME=os.path.join(self.home, "data"))
        env["LOCALAPPDATA"] = os.path.join(self.home, "data")
        proc = subprocess.Popen(
            [sys.executable, "-u", "-m", "locdepintel", "serve", "--port", "0", "--no-browser"],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.addCleanup(proc.stderr.close)
        self.addCleanup(proc.stdout.close)
        self.addCleanup(proc.wait)
        self.addCleanup(proc.kill)
        link = None
        deadline = time.time() + 15
        while time.time() < deadline and not link:
            line = proc.stdout.readline()
            match = re.search(r"http://127\.0\.0\.1:\d+/\?token=\S+", line)
            link = match.group(0) if match else None
        self.assertIsNotNone(link, "serve did not print a session link")
        base = link.split("/?")[0]
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(base + "/api/state", timeout=5)
        self.assertEqual(ctx.exception.code, 401)
        token = link.split("token=")[1]
        req = urllib.request.Request(
            base + "/api/state", headers={"Authorization": f"Bearer {token}"}
        )
        self.assertEqual(urllib.request.urlopen(req, timeout=5).status, 200)


if __name__ == "__main__":
    unittest.main()
