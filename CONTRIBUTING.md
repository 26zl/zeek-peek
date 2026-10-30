# Contributing

Issues and pull requests are welcome, especially bug reports from hardware and
Zeek setups the maintainer cannot test (OPNsense, JSON logs, unusual log
paths). Keep the project the size it is: one process, no build step, nothing
installed on the sensor.

## Setup

Python 3.11 or newer. The pinned dependencies live in `requirements.txt` and
`requirements-dev.txt`. `uv` is the quickest way to install them; plain
`python3 -m venv` and `pip`, as in the README, give the same environment.

```bash
git clone https://github.com/26zl/zeek-peek.git
cd zeek-peek
uv venv --python 3.13 .venv
uv pip install -r requirements-dev.txt
source .venv/bin/activate
cp .env.example .env    # SSH_HOST and SSH_USER, only needed for a live run
uvicorn main:app        # http://127.0.0.1:8000
```

The tests need no Zeek host: paramiko is monkeypatched and the SSH helpers are
stubbed in the fixtures.

## Checks

CI (`.github/workflows/ci.yml`) runs these on Python 3.11, 3.12 and 3.13 and
then builds the Docker image without pushing it. Run them before you open a
pull request:

```bash
ruff check .
ruff format --check .    # ruff format . rewrites the files
mypy
pytest
docker build -t zeek-peek:dev .    # optional; what the docker job does
```

Settings for ruff, mypy and pytest are in `pyproject.toml` (line length 100,
target Python 3.11, strict optional). Add a test in `tests/` for every change
in behaviour; the existing files show the pattern (FastAPI `TestClient`,
monkeypatched settings and SSH).

## Dependencies

Versions are pinned. Dependabot opens weekly pull requests for pip, the base
image and the GitHub Actions. A manual bump edits `requirements.txt` or
`requirements-dev.txt` and runs the checks above. `requirements.txt` holds
only what the server needs at runtime; development tools go in
`requirements-dev.txt`.

## Pull requests and commits

Branch from `main`, keep a pull request to one topic and say what changed,
why, and how you tested it. Commit messages are imperative sentences without a
prefix, for example `Reject DNS-rebinding with a Host-header allowlist`. CI
must be green. `main` cannot be force-pushed or deleted; changes land through
pull requests. Add a line under `Unreleased` in `CHANGELOG.md` for anything a
user would notice.

## Releases

Tag a commit on `main` as `vX.Y.Z` (semantic versioning) and push the tag.
`release.yml` reruns the CI workflow and then builds and pushes
`ghcr.io/26zl/zeek-peek` for `linux/amd64` and `linux/arm64`, tagged with the
version, `major.minor` and the short commit SHA. Every push to `main` publishes
the `main` tag the same way. Move the `Unreleased` entries of `CHANGELOG.md`
into a new version section and use them for the GitHub Release notes.

Security problems follow [SECURITY.md](SECURITY.md).
