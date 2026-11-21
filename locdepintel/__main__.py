import argparse
import json
import os
import pathlib
import sys
import webbrowser

# Checked before importing the rest of the package, which needs 3.11 features (tomllib).
if sys.version_info < (3, 11):
    found = ".".join(map(str, sys.version_info[:3]))
    sys.exit(
        f"LocDepIntel needs Python 3.11 or newer, but this is Python {found} ({sys.executable}).\n"
        "Install a current Python from https://www.python.org/downloads/ "
        "(macOS with Homebrew: brew install python@3.13),\n"
        "then run it with that version, for example: python3.13 -m locdepintel serve"
    )

from . import core, parsers, scheduler, server  # noqa: E402


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
        scheduler.notify(
            "A new malicious-package advisory affects an installed dependency. Open LocDepIntel."
        )
    pulse_result = core.sync_pulse() if online and include_pulse else {"state": "skipped"}
    return {"discovery": scanned, "security": assessed, "pulse": pulse_result}


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


def _main():
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
    glob_cmd = sp.add_parser("globals", help="Turn scanning of global installs on or off")
    glob_cmd.add_argument("state", nargs="?", choices=["on", "off"], help="Omit to show")
    sched = sp.add_parser(
        "schedule", help="Run checks periodically (launchd, systemd timer or Task Scheduler)"
    )
    sched.add_argument("--hours", type=int, default=6, help="Interval, 1-168 (default 6)")
    sp.add_parser("unschedule", help="Remove the periodic check")
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
    elif args.command == "globals":
        c = core.load_config()
        if args.state:
            c["include_global"] = args.state == "on"
            core.save_config(c)
        print("Global installs:", "on" if c.get("include_global") else "off")
        for path, kind in parsers.global_candidates():
            if pathlib.Path(path).is_dir():
                print(f"  {kind:14} {path}")
    elif args.command == "schedule":
        try:
            print("Scheduled:", scheduler.install(args.hours))
        except scheduler.SchedulerError as ex:
            sys.exit(f"locdepintel: {ex}")
    elif args.command == "unschedule":
        print("Schedule removed." if scheduler.uninstall() else "No schedule was installed.")
    else:
        parser.print_help()


def main():
    """Entry point: quiet on Ctrl+C and when output is piped into e.g. `head`."""
    try:
        _main()
        sys.stdout.flush()
    except KeyboardInterrupt:
        sys.exit(130)
    except BrokenPipeError:
        # Python docs, "Note on SIGPIPE": point stdout at devnull so the interpreter's
        # final flush does not raise a second time.
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        sys.exit(1)


if __name__ == "__main__":
    main()
