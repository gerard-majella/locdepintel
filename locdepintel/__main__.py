import argparse
import json
import os
import pathlib
import subprocess
import sys
import webbrowser

from . import core, server


def notify_macos(message):
    if sys.platform != "darwin":
        return
    # only internally generated fixed strings, not attacker-controlled advisory names
    try:
        subprocess.run(
            [
                "/usr/bin/osascript",
                "-e",
                f'display notification "{message}" with title "LocDepIntel"',
            ],
            timeout=5,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass


def run_scan(online=True, include_pulse=False):
    scanned = core.scan()
    with core.db() as con:
        before = con.execute("SELECT COALESCE(MAX(id),0) FROM events").fetchone()[0]
    assessed = core.assess() if online else {"state": "skipped"}
    with core.db() as con:
        new_malware = con.execute(
            "SELECT count(*) FROM events WHERE id>? AND kind=?", (before, "malware-alert")
        ).fetchone()[0]
    if assessed.get("state") == "ok" and new_malware:
        notify_macos(
            "A new malicious-package advisory affects an installed dependency. Open LocDepIntel."
        )
    pulse_result = core.sync_pulse() if online and include_pulse else {"state": "skipped"}
    return {"discovery": scanned, "security": assessed, "pulse": pulse_result}


def install_launchd(interval=21600):
    if sys.platform != "darwin":
        raise RuntimeError("launchd setup is supported only on macOS")
    if not 3600 <= interval <= 604800:
        raise ValueError("Interval must be 1 hour to 7 days")
    import plistlib

    directory = pathlib.Path.home() / "Library" / "LaunchAgents"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "io.github.gerard-majella.locdepintel.plist"
    args = [str(pathlib.Path(sys.executable).resolve()), "-m", "locdepintel", "run-once"]
    spec = {
        "Label": "io.github.gerard-majella.locdepintel",
        "ProgramArguments": args,
        "StartInterval": interval,
        "RunAtLoad": False,
        "StandardOutPath": str(core.home_data() / "monitor.log"),
        "StandardErrorPath": str(core.home_data() / "monitor-errors.log"),
        "WorkingDirectory": str(pathlib.Path(__file__).resolve().parent.parent),
    }
    path.write_bytes(plistlib.dumps(spec))
    os.chmod(path, 0o600)
    # use current user launchd domain; if already registered, bootout then bootstrap
    uid = os.getuid()
    subprocess.run(
        ["launchctl", "bootout", f"gui/{uid}", str(path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    p = subprocess.run(
        ["launchctl", "bootstrap", f"gui/{uid}", str(path)], capture_output=True, text=True
    )
    if p.returncode:
        raise RuntimeError(f"Could not register launchd job: {p.stderr.strip()}")
    return str(path)


def serve(port, open_browser=True):
    try:
        srv = server.make_server(port)
    except ValueError as ex:
        sys.exit(f"locdepintel: {ex}")
    except OSError as ex:
        sys.exit(f"locdepintel: cannot listen on 127.0.0.1:{port} ({ex.strerror}). Try --port.")
    print("LocDepIntel is running. Open this private link (it changes every start):")
    print(f"  {srv.launch_url}")
    print("Anyone without this link gets 401. Press Ctrl+C to stop.")
    if open_browser:
        webbrowser.open(srv.launch_url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


def main():
    parser = argparse.ArgumentParser(
        prog="locdepintel", description="Local-first dependency watchdog (read-only)"
    )
    sp = parser.add_subparsers(dest="command")
    serve_cmd = sp.add_parser("serve", help="Start local web UI")
    serve_cmd.add_argument(
        "--port", type=int, default=8765, help="Port on 127.0.0.1 (default 8765)"
    )
    serve_cmd.add_argument(
        "--no-browser", action="store_true", help="Print the session link but do not open it"
    )
    s = sp.add_parser("scan", help="Discover packages in configured roots")
    s.add_argument("--offline", action="store_true", help="Do not query OSV")
    sp.add_parser("run-once", help="Scan + advisory and Threat Pulse refresh for scheduler")
    sp.add_parser("pulse-sync", help="Fetch latest public GitHub security and malware advisories")
    sp.add_parser("status")
    sp.add_parser("inventory")
    sp.add_parser("alerts")
    sp.add_parser("export")
    conf = sp.add_parser("roots")
    conf.add_argument("paths", nargs="*", help="Replace discovery paths (none means list)")
    sched = sp.add_parser("schedule", help="Install user launchd job (macOS)")
    sched.add_argument("--hours", type=int, default=6)
    sp.add_parser("unschedule", help="Remove user launchd job")
    args = parser.parse_args()
    if args.command == "serve":
        return serve(args.port, open_browser=not args.no_browser)
    elif args.command in ("scan", "run-once"):
        print(
            json.dumps(
                run_scan(not getattr(args, "offline", False), args.command == "run-once"), indent=2
            )
        )
    elif args.command == "pulse-sync":
        print(json.dumps(core.sync_pulse(), indent=2))
    elif args.command == "status":
        print(json.dumps(core.state()["stats"], indent=2))
        print("Config:", core.config_path())
        print("Database:", core.db_path())
    elif args.command == "inventory":
        for p in core.inventory():
            print(f'{p["ecosystem"]:5} {p["name"]:36.36} {p["version"]:16.16}  {p["env"]}')
    elif args.command == "alerts":
        for x in core.state()["findings"]:
            print(
                f'{x["kind"].upper()} | {x["name"]}@{x["version"]} | {x["advisory"]} | {x["env"]}'
            )
    elif args.command == "export":
        print(json.dumps(core.export(), indent=2))
    elif args.command == "roots":
        if args.paths:
            c = core.load_config()
            c["roots"] = [str(pathlib.Path(p).expanduser().resolve()) for p in args.paths]
            core.save_config(c)
        print("\n".join(core.load_config()["roots"]))
    elif args.command == "schedule":
        print("Scheduled with launchd:", install_launchd(args.hours * 3600))
    elif args.command == "unschedule":
        if sys.platform != "darwin":
            parser.error("macOS only")
        path = (
            pathlib.Path.home()
            / "Library"
            / "LaunchAgents"
            / "io.github.gerard-majella.locdepintel.plist"
        )
        if path.exists():
            subprocess.run(
                ["launchctl", "bootout", f"gui/{os.getuid()}", str(path)], capture_output=True
            )
            path.unlink()
        print("Schedule removed.")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
