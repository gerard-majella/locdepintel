# LocDepIntel

**Local dependency intelligence.** Find every Python environment and JavaScript project on your machine, build a live inventory of the exact package versions installed, and get alerted when one of them matches a known **malicious package** or **vulnerability** advisory.

[![CI](https://github.com/gerard-majella/locdepintel/actions/workflows/ci.yml/badge.svg)](https://github.com/gerard-majella/locdepintel/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Dependencies](https://img.shields.io/badge/runtime%20deps-0-brightgreen)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

![LocDepIntel dashboard (demo data)](docs/screenshot.png)

## Why

Supply-chain attacks (typosquats, hijacked maintainer accounts, malicious install scripts) land on developer laptops first. Most SCA tools scan one repository in CI. Your laptop has dozens of forgotten virtualenvs, `node_modules` folders and globally installed CLIs that nobody scans. LocDepIntel answers one question: **"Is anything installed on this machine right now named in a malware or vulnerability advisory?"**

## Features

- **Machine-wide discovery** of the folders you choose (bounded depth, symlinks not followed):
  - Python: virtualenvs, conda environments, `poetry.lock`, `uv.lock`, `Pipfile.lock`
  - JavaScript: `package-lock.json` (v1 to v3), `yarn.lock` (classic and Berry), `pnpm-lock.yaml` (v5, v6, v9)
  - Optional global installs: `npm -g` (including nvm and Homebrew), user and system site-packages, pipx tools
- **Exact-version matching** against [OSV.dev](https://osv.dev), including the OpenSSF malicious-packages feed (`MAL-` advisories).
- **Action Center**: findings grouped by package and version across every location, malware first, with copy-paste remediation for the right tool (`yarn why`, `pnpm why`, `uv tree --invert`, `poetry show --why`, ...).
- **Threat Pulse**: newest malware and reviewed advisories from the GitHub Advisory Database, cross-referenced with your inventory.
- **History**: every package first observed, removed, retired from scope, or newly flagged, in local SQLite with versioned migrations.
- **Background checks** on macOS (launchd), Linux (systemd user timer, or a cron line where systemd is unavailable) and Windows (Task Scheduler), with a desktop alert on new malware matches.
- **Zero runtime dependencies**: Python standard library only. Nothing to `pip install`, so nothing in the tool itself to be supply-chain attacked.

## Security design

| Concern | How it is handled |
|---|---|
| Executing hostile code during a scan | Never. Reads metadata text and lockfiles only: no imports, no `pip`/`npm` calls, never runs the environment's `python`. A test plants import, `.pth`, `sitecustomize`, `setup.py`, fake interpreter and npm `preinstall` traps and proves none fires. |
| Other local users or processes reading your inventory | Every request needs a random per-run token. The launch link exchanges it for an `HttpOnly`, `SameSite=Strict` cookie and removes it from the address bar. |
| DNS rebinding and cross-site requests | Loopback bind, `Host` allow-list, `Origin` and `Sec-Fetch-Site` checks, and state changes must be `application/json` (an HTML form cannot send that). |
| Malicious advisory text or package names (stored XSS) | Escaped before rendering, plus a strict CSP with no inline script. Browser tests inject both and check nothing runs. |
| Command injection via "open in Terminal / reveal" and desktop alerts | Only paths already in the scan database are accepted; values travel as argv or environment data, never through a shell or into script source. |
| Leaking internal package names | Only public-registry packages are sent to OSV / deps.dev. Workspace members, local paths, git dependencies, private indexes and `npm link` targets are skipped. File paths never leave the machine. |
| False reassurance | Partial scans, unavailable folders and failed advisory checks are reported and never shown as "clean". Packages are only retired when the folder they live in was fully read. |

See [SECURITY.md](SECURITY.md) for the threat model and how to report issues.

## Quick start

Requires Python 3.11+.

```bash
git clone https://github.com/gerard-majella/locdepintel.git
cd locdepintel
python3 -m locdepintel serve        # Windows: py -3 -m locdepintel serve
```

Your browser opens a private session link (also printed in the terminal; it changes every start). Pick the folders to scan and click **Start first scan**.

Or install it as a command:

```bash
pipx install git+https://github.com/gerard-majella/locdepintel.git
locdepintel serve
```

## CLI

| Command | What it does |
|---|---|
| `locdepintel serve [--port N] [--no-browser]` | Start the dashboard on `127.0.0.1` |
| `locdepintel roots ~/code ~/work` | Set which folders to scan |
| `locdepintel globals on` | Also scan global installs (`npm -g`, site-packages, pipx) |
| `locdepintel scan [--offline]` | Discover environments and check them against OSV |
| `locdepintel alerts` | Print active findings |
| `locdepintel inventory` | Print every installed package |
| `locdepintel export > report.json` | Full JSON export |
| `locdepintel pulse-sync` | Refresh Threat Pulse from GitHub Advisories |
| `locdepintel schedule --hours 6` | Check in the background (macOS, Linux, Windows) |
| `locdepintel unschedule` | Remove the background check |

## Architecture

```
locdepintel/
  parsers.py     lockfile and environment readers (pure functions, no I/O beyond reading)
  scanner.py     walks folders, keeps the inventory current, retires out-of-scope data
  advisories.py  OSV, deps.dev and GitHub Advisory Database clients (the only network code)
  store.py       SQLite with versioned, append-only migrations
  reports.py     read-only views for the dashboard and CLI
  server.py      local web UI and JSON API (token auth, CSRF and rebinding protection)
  scheduler.py   launchd / systemd / Task Scheduler jobs and desktop alerts
  static/        dashboard (vanilla JS, no build step)
```

## Limitations

- Not yet: Cargo, Go modules, Yarn Plug'n'Play installs without a lockfile, Bun.
- Lockfiles describe what a project *would* install; an environment can drift from its lockfile.
- "No findings" means no **published** advisory matches, not that the code is safe.
- Advisory checks need internet access; inventory works offline.

## Running tests

```bash
python3 -m unittest discover -s tests -v
```

Tests run offline and never touch your real data folder or the network. The browser tests in `tests/test_ui_browser.py` run when Playwright is installed (`pip install playwright && playwright install chromium`) and are skipped otherwise; CI runs them in a separate job.

## Roadmap

- Flag npm packages that run install scripts (`hasInstallScript`)
- Typosquat detection against popular package names
- SARIF output (GitHub code scanning) and CycloneDX SBOM export
- Cargo and Go module support

## License

MIT
