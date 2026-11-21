# Changelog

## 0.9.0

Security
- Per-run session token for the local API; HttpOnly SameSite=Strict cookie; JSON-only,
  same-origin state changes. Previously any local process could read the inventory or change
  the scan folders.
- Desktop alert text is passed as data, never spliced into AppleScript.

Coverage
- Yarn (classic and Berry), pnpm (v5, v6, v9), Poetry, uv, Pipfile, conda environments,
  egg-info metadata and Windows layouts.
- Opt-in global installs: npm -g (prefix found from the node binary, nvm, Homebrew, APPDATA),
  user and system site-packages, pipx. Symlinked registry installs are followed; npm link
  targets are not, so private names stay private.

Correctness
- Removing a folder from the settings retires its packages, findings and environments; a
  partial scan only protects the folders that could not be read; vanished environments are
  marked missing.
- The "unique advisories" count reported the last package's count instead of the total.
- Two checks in the same second reported zero new findings (timestamps now have ms precision).
- PEP 503 name normalisation used everywhere (Threat Pulse could miss dotted names).
- Server errors return JSON 500 with an id instead of dropping the connection; the CLI no
  longer prints a traceback when piped into `head`.

Platform
- Background checks on Linux (systemd user timer, cron fallback) and Windows (Task Scheduler).
- Configurable `--port`. Minimum Python is 3.11 (3.10 reached end of life in October 2026).

Internals
- Versioned SQLite migrations with an advisory cache; parallel OSV downloads.
- core.py split into settings, store, scanner, advisories and reports; readable templates.
- Tests organised by feature, real browser tests, code-execution trap test, CI lint job.

## 0.8.0 (first public release as LocDepIntel)

- Renamed from DepWatch to LocDepIntel (local dependency intelligence). New data directory, so earlier DepWatch data is not migrated.
- Fix: npm workspace members (lockfile keys such as `packages/app`) were treated as public packages and sent to OSV, leaking internal package names. They are now skipped.
- Fix: SQL queries used double-quoted string literals, which SQLite treats as a deprecated fallback and can reject when built with `SQLITE_DQS=0`.
- User-Agent now reports the real version instead of hard-coded `0.1` / `0.5`.
- Added CI (Linux, macOS, Windows; Python 3.10 and 3.13), SECURITY.md, packaging metadata.

## 0.7.0 and earlier (as DepWatch, unreleased)

First-run onboarding, grouped inventory, Action Center, Threat Pulse (GitHub Advisory Database), SQLite history, macOS launchd scheduling.
