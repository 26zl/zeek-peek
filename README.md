# zeek-peek

Agentless Zeek log viewer for pfSense, OPNsense, and small Zeek
sensors (Netgate, Protectli, Raspberry Pi, mini-PCs). SFTP pulls,
DuckDB storage, browser UI. No SIEM, no Grafana, no agent on the
device.

## Why

I built this for my own Netgate 1100 (1 GB RAM, 8 GB eMMC): Zeek
already runs on the firewall, and the built-in pfSense log viewer is
heavy enough that browsing logs there is painful. zeek-peek offloads
the rendering to another machine, so the firewall just serves log
bytes over SFTP, which it does cheaply.

Anyone running Zeek on a small box should get the same benefit.
Built for:

- pfSense / pfSense Plus on Netgate appliances or any x86 mini-PC
  (Protectli, Qotom, Topton, generic NUCs)
- Standalone Zeek on a Raspberry Pi, mini-PC, VM, or LXC container

It should also work with OPNsense and the `os-zeek` plugin when the
Zeek log directory and SSH access are configured correctly.

The only requirement is Zeek writing TSV logs to disk and an SSH user
that can read them. JSON logs aren't supported yet.

## Stack

Python (FastAPI), DuckDB, vanilla JS. One process, no build step.

## Run locally

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env       # set SSH_HOST and SSH_USER
uvicorn main:app
```

Open <http://127.0.0.1:8000>.

## Run in Docker

```bash
mkdir -p secrets
cp ~/.ssh/your_key secrets/id_key
ssh-keyscan -H your.zeek.host > secrets/known_hosts
cp .env.example .env       # set SSH_HOST and SSH_USER

docker compose up -d
```

## Configuration

All settings live in `.env`. See `.env.example` for the full list.
Required: `SSH_HOST`, `SSH_USER`. Sensible defaults for everything else.

## Storage

Logs are streamed into an embedded **DuckDB** file. The example config
sets `DB_PATH=data/zeek.duckdb`. A background worker pulls new bytes
from each log on `INGEST_INTERVAL` (default 30 s) and inserts them into
`log_<name>` tables. The API queries DuckDB and falls back to SFTP only
when a table is empty (cold start).

To disable, set `DB_PATH=` in `.env` and the dashboard reverts to the
SFTP-only path. The Docker setup persists the DB in a named volume
(`zeek-data`).

## Endpoints

- `GET /`: frontend
- `GET /api/health`: liveness probe
- `GET /api/status`: SSH state, available logs, DB ingest state
- `GET /api/log/{name}?limit=&since=&tail=&source=auto|db|ssh`: last
  rows of `{name}.log`

## Security

- Bind to `127.0.0.1` (default). No built-in auth: put it behind a
  reverse proxy or restrict at the network layer if exposed.
- Strict SSH host-key verification is always used. Populate
  `SSH_KNOWN_HOSTS` with `ssh-keyscan -H <host>` or rely on the system
  `known_hosts`.
- Reads are SFTP-only; no shell on the remote host.

## Development

```bash
pip install -r requirements-dev.txt
ruff check . && ruff format --check . && mypy && pytest
```

## License

MIT, see [LICENSE](LICENSE).
