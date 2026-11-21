"""Scheduling backends for macOS, Linux and Windows (system commands mocked)."""

import os
import pathlib
import plistlib
import shutil
import subprocess
import sys
import unittest
from unittest import mock

from helpers import isolate

from locdepintel import scheduler


def ok(*_args, **_kwargs):
    return subprocess.CompletedProcess([], 0, "", "")


class SchedulerTestCase(unittest.TestCase):
    def setUp(self):
        self.home = isolate(self)  # data folder is self.home / "data"
        for patcher in (
            mock.patch.object(pathlib.Path, "home", lambda: self.home),
            mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": str(self.home / ".config")}),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)


class IntervalTests(SchedulerTestCase):
    def test_interval_bounds(self):
        for bad in (0, 169, -1, "6"):
            with self.assertRaises(scheduler.SchedulerError):
                scheduler.install(bad)


class LinuxTests(SchedulerTestCase):
    def test_install_writes_units_and_enables_timer(self):
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            return ok()

        with (
            mock.patch.object(sys, "platform", "linux"),
            mock.patch.object(scheduler.shutil, "which", return_value="/usr/bin/systemctl"),
            mock.patch.object(scheduler.subprocess, "run", side_effect=fake_run),
        ):
            scheduler.install(4)
        unit_dir = self.home / ".config/systemd/user"
        timer = (unit_dir / "locdepintel.timer").read_text()
        service = (unit_dir / "locdepintel.service").read_text()
        self.assertIn("OnUnitActiveSec=4h", timer)
        self.assertIn("Type=oneshot", service)
        self.assertIn('"-m" "locdepintel" "run-once"', service)
        self.assertIn(["systemctl", "--user", "enable", "--now", "locdepintel.timer"], calls)

        with (
            mock.patch.object(sys, "platform", "linux"),
            mock.patch.object(scheduler.shutil, "which", return_value="/usr/bin/systemctl"),
            mock.patch.object(scheduler.subprocess, "run", side_effect=fake_run),
        ):
            self.assertTrue(scheduler.uninstall())
        self.assertFalse((unit_dir / "locdepintel.timer").exists())
        self.assertIn(["systemctl", "--user", "disable", "--now", "locdepintel.timer"], calls)

    def test_no_user_session_gives_cron_line_instead_of_traceback(self):
        failing = subprocess.CompletedProcess([], 1, "", "Failed to connect to bus")
        with (
            mock.patch.object(sys, "platform", "linux"),
            mock.patch.object(scheduler.shutil, "which", return_value="/usr/bin/systemctl"),
            mock.patch.object(scheduler.subprocess, "run", return_value=failing),
        ):
            with self.assertRaisesRegex(scheduler.SchedulerError, r"crontab -e[\s\S]*0 \*/6"):
                scheduler.install(6)

    def test_cron_hint_is_shell_safe(self):
        with mock.patch.object(scheduler, "_workdir", return_value="/home/o'brien/$HOME/src"):
            line = scheduler._cron_hint(6)
        command = line.split(" ", 5)[5].split(" &&")[0]
        out = subprocess.run(["sh", "-c", f"echo {command[3:]}"], capture_output=True, text=True)
        self.assertEqual(out.stdout.strip(), "/home/o'brien/$HOME/src")  # no $ expansion

    def test_exec_start_quoting_survives_spaces_and_percent(self):
        with mock.patch.object(scheduler, "_python", return_value="/opt/My Py%/bin/python3"):
            service, _ = scheduler.systemd_units(6)
        self.assertIn('ExecStart="/opt/My Py%%/bin/python3" "-m"', service)

    @unittest.skipUnless(shutil.which("systemd-analyze"), "systemd-analyze not installed")
    def test_generated_units_pass_systemd_analyze_verify(self):
        awkward = self.home / "My Projects 100%" / "locdepintel-src"
        awkward.mkdir(parents=True)
        with mock.patch.object(scheduler, "_workdir", return_value=str(awkward)):
            service, timer = scheduler.systemd_units(6)
        directory = self.home / "units"
        directory.mkdir()
        (directory / "locdepintel.service").write_text(service)
        (directory / "locdepintel.timer").write_text(timer)
        result = subprocess.run(
            [
                "systemd-analyze",
                "verify",
                "--man=no",
                str(directory / "locdepintel.timer"),
                str(directory / "locdepintel.service"),
            ],
            capture_output=True,
            text=True,
        )
        problems = [
            line
            for line in result.stderr.splitlines()
            if "locdepintel" in line and "Failed to" not in line  # no bus here is fine
        ]
        self.assertEqual(problems, [], result.stderr)


class MacTests(SchedulerTestCase):
    def test_launchd_plist(self):
        calls = []
        with (
            mock.patch.object(sys, "platform", "darwin"),
            mock.patch.object(scheduler.os, "getuid", return_value=501, create=True),
            mock.patch.object(
                scheduler.subprocess, "run", side_effect=lambda c, **k: calls.append(c) or ok()
            ),
        ):
            scheduler.install(12)
        plist = plistlib.loads(
            (self.home / "Library/LaunchAgents" / f"{scheduler.LABEL}.plist").read_bytes()
        )
        self.assertEqual(plist["StartInterval"], 12 * 3600)
        self.assertEqual(plist["ProgramArguments"][1:], ["-m", "locdepintel", "run-once"])
        self.assertIn(["launchctl", "bootstrap", "gui/501", mock.ANY], calls)


class WindowsTests(SchedulerTestCase):
    def test_hourly_daily_and_invalid_intervals(self):
        self.assertEqual(scheduler.windows_schedule_args(6), ["/SC", "HOURLY", "/MO", "6"])
        self.assertEqual(scheduler.windows_schedule_args(48), ["/SC", "DAILY", "/MO", "2"])
        with self.assertRaises(scheduler.SchedulerError):
            scheduler.windows_schedule_args(30)

    def test_schtasks_runs_wrapper_script(self):
        calls = []
        with (
            mock.patch.object(sys, "platform", "win32"),
            mock.patch.object(
                scheduler, "_python", return_value=r"C:\Program Files\Python313\python.exe"
            ),
            mock.patch.object(
                scheduler.subprocess, "run", side_effect=lambda c, **k: calls.append(c) or ok()
            ),
        ):
            scheduler.install(6)
        wrapper = self.home / "data/run-once.cmd"
        text = wrapper.read_text()
        self.assertIn('"C:\\Program Files\\Python313\\python.exe" -m locdepintel run-once', text)
        self.assertIn("cd /d", text)
        cmd = calls[0]
        self.assertEqual(cmd[:4], ["schtasks", "/Create", "/TN", "LocDepIntel"])
        self.assertEqual(cmd[cmd.index("/TR") + 1], f'"{wrapper}"')
        self.assertLess(len(cmd[cmd.index("/TR") + 1]), 261)  # schtasks /TR limit


class NotifyTests(unittest.TestCase):
    def test_message_is_passed_as_data_not_code(self):
        hostile = 'x" & do shell script "touch /tmp/pwned" & "'
        with (
            mock.patch.object(sys, "platform", "darwin"),
            mock.patch.object(scheduler.subprocess, "run") as run,
        ):
            scheduler.notify(hostile)
        argv = run.call_args.args[0]
        self.assertEqual(argv[-2], hostile)  # an argument, not part of the script
        self.assertNotIn(hostile, argv[2])

    def test_windows_uses_environment_variables(self):
        with (
            mock.patch.object(sys, "platform", "win32"),
            mock.patch.object(scheduler.subprocess, "Popen") as popen,
        ):
            scheduler.notify("hello")
        self.assertEqual(popen.call_args.kwargs["env"]["LDI_MESSAGE"], "hello")
        self.assertNotIn("hello", " ".join(popen.call_args.args[0]))

    def test_linux_without_notify_send_is_silent(self):
        with (
            mock.patch.object(sys, "platform", "linux"),
            mock.patch.object(scheduler.shutil, "which", return_value=None),
        ):
            self.assertFalse(scheduler.notify("hello"))


if __name__ == "__main__":
    unittest.main()
