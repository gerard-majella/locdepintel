# Security policy

## Reporting a vulnerability

Please do not open a public issue for security problems in LocDepIntel itself.
Use GitHub's private reporting instead: **Security tab > Report a vulnerability** on this repository.

I aim to acknowledge reports within 7 days.

## Scope

In scope: the local web UI and API (`127.0.0.1:8765`), the scanner, the scheduler integration, and how advisory data is parsed and rendered.

## Threat model (summary)

- The UI binds to loopback only and rejects requests with an unexpected `Host` or `Origin` header (DNS rebinding and cross-site request protection).
- Scanning is read-only. LocDepIntel parses `METADATA` files and `package-lock.json`; it never imports, executes or installs scanned code.
- Advisory text from OSV and GitHub is treated as untrusted and HTML-escaped before rendering; a strict Content-Security-Policy blocks inline script.
- Package names and versions (not file paths) are sent to `api.osv.dev` and `api.deps.dev` for matching. Workspace-local npm packages are excluded so internal names are not disclosed.
- Known limitation: any process running as **another local user** can reach the loopback API. See the roadmap item on per-session API tokens.
