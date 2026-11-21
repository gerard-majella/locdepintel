# Security policy

## Reporting a vulnerability

Please do not open a public issue for security problems in LocDepIntel itself.
Use GitHub's private reporting instead: **Security tab > Report a vulnerability** on this repository.

I aim to acknowledge reports within 7 days.

## Scope

In scope: the local web UI and API (`127.0.0.1:8765`), the scanner, the scheduler integration, and how advisory data is parsed and rendered.

## Threat model (summary)

Assets: the list of packages and file paths on your machine, and the integrity of the scan settings.

- **Remote websites** (malicious pages open in your browser): blocked by the loopback bind, `Host`
  allow-list (DNS rebinding), per-run token, `SameSite=Strict` cookie, and `Origin` /
  `Sec-Fetch-Site` / JSON content-type checks on every state change.
- **Other local users and processes** without the token: every request returns 401.
- **Hostile project folders**: scanning is read-only. LocDepIntel parses metadata and lockfiles
  and never imports, executes or installs scanned code, including the environment's own
  interpreter. Symlinks are not followed during discovery.
- **Hostile advisory or package text**: HTML-escaped before rendering; a strict
  Content-Security-Policy blocks inline script as a second layer.
- **Privacy**: only public-registry package names and versions are sent to `api.osv.dev`,
  `api.deps.dev` and `api.github.com`. Workspace members, local paths, git dependencies, private
  indexes and `npm link` targets are not sent. File paths never leave the machine.

Out of scope: malware already running as your own user account (it can read your files directly),
and the correctness of third-party advisory databases.
