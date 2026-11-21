# Changelog

## 0.8.0 (first public release as LocDepIntel)

- Renamed from DepWatch to LocDepIntel (local dependency intelligence). New data directory, so earlier DepWatch data is not migrated.
- Fix: npm workspace members (lockfile keys such as `packages/app`) were treated as public packages and sent to OSV, leaking internal package names. They are now skipped.
- Fix: SQL queries used double-quoted string literals, which SQLite treats as a deprecated fallback and can reject when built with `SQLITE_DQS=0`.
- User-Agent now reports the real version instead of hard-coded `0.1` / `0.5`.
- Added CI (Linux, macOS, Windows; Python 3.10 and 3.13), SECURITY.md, packaging metadata.

## 0.7.0 and earlier (as DepWatch, unreleased)

First-run onboarding, grouped inventory, Action Center, Threat Pulse (GitHub Advisory Database), SQLite history, macOS launchd scheduling.
