# Changelog

All notable changes to zeek-peek are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Each release is a
`vX.Y.Z` tag with notes on [GitHub Releases](https://github.com/26zl/zeek-peek/releases)
and an image at `ghcr.io/26zl/zeek-peek`.

## [Unreleased]

### Added

- `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md` and `.editorconfig`.

### Changed

- The container image is built on `python:3.14-slim`, pinned by digest (#3).
- Pinned dependencies are kept current by weekly Dependabot updates (#2), among
  them FastAPI, uvicorn, paramiko 5 and DuckDB 1.5.
- The release workflow grants `packages: write` to the publish job only, and
  the Docker actions in CI and release are pinned to commit SHAs.

### Fixed

- The status endpoint no longer returns raw exception text when the database
  check fails; the detail goes to the server log instead (#1).

### Security

- Requests whose `Host` header is not on the `ALLOWED_HOSTS` allowlist
  (default `127.0.0.1,localhost`) are rejected, which stops DNS rebinding
  against a dashboard bound to localhost (#16).

## [0.1.0] - 2026-07-03

First tagged release.

### Added

- Reads Zeek TSV logs over SFTP only, with no shell on the remote host, strict
  SSH host-key verification and a fail-fast backoff when the host is
  unreachable.
- Embedded DuckDB storage with a background ingest worker, log-rotation
  detection and per-table row retention (`RETENTION_ROWS`) that bounds disk
  growth.
- FastAPI backend and a vanilla-JS dashboard (filter, sort, auto-refresh) that
  serves from DuckDB and falls back to SFTP on a cold start.
- Hardened container: non-root, read-only root filesystem, dropped
  capabilities, digest-pinned base image; published as
  `ghcr.io/26zl/zeek-peek:0.1.0`.
- CI on Python 3.11, 3.12 and 3.13.

[Unreleased]: https://github.com/26zl/zeek-peek/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/26zl/zeek-peek/releases/tag/v0.1.0
