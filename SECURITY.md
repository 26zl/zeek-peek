# Security policy

## Reporting a vulnerability

Report security problems privately through GitHub:
[Report a vulnerability](https://github.com/26zl/zeek-peek/security/advisories/new)
(the Security tab of this repository). Do not open a public issue for anything
that could be exploited before it is fixed. Expect a first reply within seven
days. A fix ships as a new `vX.Y.Z` tag and a new `ghcr.io/26zl/zeek-peek`
image, and the advisory is published with it.

Use an ordinary [issue](https://github.com/26zl/zeek-peek/issues) for bugs
that are not sensitive.

## Scope

zeek-peek runs on a machine of your own and only ever reads from the Zeek
host over SFTP. Reports that matter most:

- Anything that lets the dashboard run commands on the Zeek host, read files
  other than the configured logs, or weaken the strict SSH host-key check.
- A way around the `Host` header allowlist (`ALLOWED_HOSTS`), the CORS origin
  list (`ALLOWED_ORIGINS`) or the `MAX_LIMIT` and `MAX_TAIL_BYTES` caps, or
  anything that lets a page on another origin read log data.
- Injection through log contents: a crafted Zeek log line that breaks out of
  the table in the browser, the DuckDB queries or the JSON responses.
- Container hardening that does not hold: non-root user, read-only root
  filesystem, dropped capabilities.

Not in scope: the dashboard has no authentication by design and binds to
`127.0.0.1` by default; see the Security section of the README. Exposing it
without a reverse proxy or a network restriction is a deployment choice, not a
vulnerability. Problems in Zeek, pfSense, OPNsense or a dependency belong with
those projects, although a dependency advisory that affects zeek-peek is
welcome as an issue or a pull request.

## Supported versions

Only the latest tagged release and the `main` branch are supported. Fixes
land on `main` and ship with the next tag; Dependabot keeps the Python
packages, the base image and the GitHub Actions current in between.
