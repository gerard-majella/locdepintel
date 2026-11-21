"""Periodic background checks and desktop alerts on macOS, Linux and Windows.

Each backend registers a per-user job (no administrator rights) that runs
``python -m locdepintel run-once`` from this installation.

* macOS: launchd agent in ~/Library/LaunchAgents
* Linux: systemd user service + timer in ~/.config/systemd/user
* Windows: Task Scheduler task running a small .cmd wrapper
"""

import os
import pathlib
import plistlib
import shlex
import shutil
import subprocess
import sys

from . import settings

LABEL = "io.github.gerard-majella.locdepintel"
UNIT = "locdepintel"
WINDOWS_TASK = "LocDepIntel"
MIN_HOURS, MAX_HOURS = 1, 168


class SchedulerError(RuntimeError):
    """A scheduling problem with a message meant for the user."""


def _python():
    return str(pathlib.Path(sys.executable).resolve())


def _workdir():
    """Folder that contains the locdepintel package, so ``-m locdepintel`` imports it."""
    return str(pathlib.Path(__file__).resolve().parent.parent)


def _check_hours(hours):
    if not isinstance(hours, int) or not MIN_HOURS <= hours <= MAX_HOURS:
        raise SchedulerError(f"Interval must be {MIN_HOURS} to {MAX_HOURS} hours")


def _run(cmd, **kwargs):
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


# ----------------------------------------------------------------------- macOS


def _launchd_path():
    return pathlib.Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist"


def launchd_spec(hours):
    return {
        "Label": LABEL,
        "ProgramArguments": [_python(), "-m", "locdepintel", "run-once"],
        "StartInterval": hours * 3600,
        "RunAtLoad": False,
        "StandardOutPath": str(settings.home_data() / "monitor.log"),
        "StandardErrorPath": str(settings.home_data() / "monitor-errors.log"),
        "WorkingDirectory": _workdir(),
    }


def _install_launchd(hours):
    path = _launchd_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(plistlib.dumps(launchd_spec(hours)))
    os.chmod(path, 0o600)
    domain = f"gui/{os.getuid()}"
    _run(["launchctl", "bootout", domain, str(path)])  # ignore "not loaded"
    result = _run(["launchctl", "bootstrap", domain, str(path)])
    if result.returncode:
        raise SchedulerError(f"launchctl bootstrap failed: {result.stderr.strip()}")
    return f"launchd agent {path}"


def _uninstall_launchd():
    path = _launchd_path()
    if path.exists():
        _run(["launchctl", "bootout", f"gui/{os.getuid()}", str(path)])
        path.unlink()
        return True
    return False


# ----------------------------------------------------------------------- Linux


def _systemd_dir():
    base = os.environ.get("XDG_CONFIG_HOME") or str(pathlib.Path.home() / ".config")
    return pathlib.Path(base) / "systemd" / "user"


def _systemd_quote(arg):
    """Quote one ExecStart argument (systemd.syntax: double quotes, escape \\ " and %)."""
    escaped = arg.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%")
    return f'"{escaped}"'


def systemd_units(hours):
    exec_start = " ".join(_systemd_quote(a) for a in (_python(), "-m", "locdepintel", "run-once"))
    service = (
        "[Unit]\n"
        "Description=LocDepIntel dependency advisory check\n"
        "Documentation=https://github.com/gerard-majella/locdepintel\n\n"
        "[Service]\n"
        "Type=oneshot\n"
        # WorkingDirectory takes the rest of the line literally (spaces are fine); quotes
        # would become part of the path. Only % specifiers need escaping.
        f"WorkingDirectory={_workdir().replace('%', '%%')}\n"
        f"ExecStart={exec_start}\n"
        "Nice=10\n"
        "IOSchedulingClass=idle\n"
    )
    timer = (
        "[Unit]\n"
        "Description=Run LocDepIntel periodically\n\n"
        "[Timer]\n"
        "OnBootSec=10min\n"
        f"OnUnitActiveSec={hours}h\n"
        "RandomizedDelaySec=5min\n\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )
    return service, timer


def _cron_hint(hours):
    log = shlex.quote(str(settings.home_data() / "monitor.log"))
    command = f"cd {shlex.quote(_workdir())} && {shlex.quote(_python())} -m locdepintel run-once"
    every = f"0 */{hours} * * *" if hours < 24 else f"0 9 */{max(1, hours // 24)} * *"
    # cron treats an unescaped % as a newline
    return f"{every} {command} >> {log} 2>&1".replace("%", "\\%")


def _install_systemd(hours):
    if not shutil.which("systemctl"):
        raise SchedulerError(
            "systemd is not available. Add this line with 'crontab -e' instead:\n  "
            + _cron_hint(hours)
        )
    probe = _run(["systemctl", "--user", "show-environment"])
    if probe.returncode:
        raise SchedulerError(
            "No systemd user session is running (common on WSL, containers and servers "
            "without a login session). Add this line with 'crontab -e' instead:\n  "
            + _cron_hint(hours)
        )
    directory = _systemd_dir()
    directory.mkdir(parents=True, exist_ok=True)
    service, timer = systemd_units(hours)
    (directory / f"{UNIT}.service").write_text(service)
    (directory / f"{UNIT}.timer").write_text(timer)
    for cmd in (
        ["systemctl", "--user", "daemon-reload"],
        ["systemctl", "--user", "enable", "--now", f"{UNIT}.timer"],
    ):
        result = _run(cmd)
        if result.returncode:
            raise SchedulerError(f"{' '.join(cmd)} failed: {result.stderr.strip()}")
    return f"systemd user timer {directory / (UNIT + '.timer')}"


def _uninstall_systemd():
    directory = _systemd_dir()
    files = [directory / f"{UNIT}.service", directory / f"{UNIT}.timer"]
    if not any(f.exists() for f in files):
        return False
    if shutil.which("systemctl"):
        _run(["systemctl", "--user", "disable", "--now", f"{UNIT}.timer"])
    for f in files:
        if f.exists():
            f.unlink()
    if shutil.which("systemctl"):
        _run(["systemctl", "--user", "daemon-reload"])
    return True


# --------------------------------------------------------------------- Windows


def _windows_wrapper():
    return settings.home_data() / "run-once.cmd"


def windows_wrapper_text():
    python = pathlib.Path(_python())
    pythonw = python.with_name("pythonw.exe")
    exe = pythonw if pythonw.exists() else python  # pythonw avoids a console window
    log = settings.home_data() / "monitor.log"
    return (
        "@echo off\r\n"
        f'cd /d "{_workdir()}"\r\n'
        f'"{exe}" -m locdepintel run-once >> "{log}" 2>&1\r\n'
    )


def windows_schedule_args(hours):
    if hours <= 23:
        return ["/SC", "HOURLY", "/MO", str(hours)]
    if hours % 24 == 0:
        return ["/SC", "DAILY", "/MO", str(hours // 24)]
    raise SchedulerError("On Windows the interval must be 1 to 23 hours or a multiple of 24")


def _install_windows(hours):
    schedule = windows_schedule_args(hours)
    wrapper = _windows_wrapper()
    wrapper.write_text(windows_wrapper_text())
    cmd = ["schtasks", "/Create", "/TN", WINDOWS_TASK, "/TR", f'"{wrapper}"', *schedule, "/F"]
    result = _run(cmd)
    if result.returncode:
        raise SchedulerError(f"schtasks failed: {(result.stderr or result.stdout).strip()}")
    return f"Task Scheduler task '{WINDOWS_TASK}'"


def _uninstall_windows():
    result = _run(["schtasks", "/Delete", "/TN", WINDOWS_TASK, "/F"])
    wrapper = _windows_wrapper()
    if wrapper.exists():
        wrapper.unlink()
    return result.returncode == 0


# ---------------------------------------------------------------------- public


def install(hours=6):
    _check_hours(hours)
    if sys.platform == "darwin":
        return _install_launchd(hours)
    if sys.platform == "win32":
        return _install_windows(hours)
    return _install_systemd(hours)


def uninstall():
    if sys.platform == "darwin":
        return _uninstall_launchd()
    if sys.platform == "win32":
        return _uninstall_windows()
    return _uninstall_systemd()


# ----------------------------------------------------------------- notifications

ALERT_TITLE = "LocDepIntel"
_WINDOWS_TOAST = (
    "Add-Type -AssemblyName System.Windows.Forms;"
    "$n=New-Object System.Windows.Forms.NotifyIcon;"
    "$n.Icon=[System.Drawing.SystemIcons]::Warning;$n.Visible=$true;"
    "$n.ShowBalloonTip(10000,$env:LDI_TITLE,$env:LDI_MESSAGE,'Warning');"
    "Start-Sleep -Seconds 11;$n.Dispose()"
)


def notify(message):
    """Best-effort desktop alert. Text is passed as data (argv/env), never as code."""
    try:
        if sys.platform == "darwin":
            script = (
                "on run argv\n"
                "display notification (item 1 of argv) with title (item 2 of argv)\n"
                "end run"
            )
            cmd = ["/usr/bin/osascript", "-e", script, message, ALERT_TITLE]
            env = None
        elif sys.platform == "win32":
            cmd = ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", _WINDOWS_TOAST]
            env = dict(os.environ, LDI_TITLE=ALERT_TITLE, LDI_MESSAGE=message)
        else:
            sender = shutil.which("notify-send")
            if not sender:
                return False
            cmd = [sender, "--urgency=critical", "--app-name", ALERT_TITLE, ALERT_TITLE, message]
            env = None
        if sys.platform == "win32":  # the balloon must stay alive ~10 s; do not block the scan
            subprocess.Popen(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.run(cmd, timeout=15, env=env, capture_output=True)
        return True
    except (OSError, subprocess.SubprocessError):
        return False
