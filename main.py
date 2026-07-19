"""zeek-peek. FastAPI backend that reads Zeek logs over SSH."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import threading
import time
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from typing import Any, TypedDict, TypeVar

import duckdb
import paramiko
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response


class CachedLog(TypedDict):
    fields: list[str]
    rows: list[dict[str, Any]]
    size: int


def _load_env_file(path: str = ".env") -> None:
    """Load KEY=value lines from a .env file for local dev."""
    p = Path(path)
    if not p.exists():
        return
    for line in p.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


_load_env_file()

_T = TypeVar("_T", int, float)


def _env(name: str, default: str | None = None) -> str | None:
    v = os.getenv(name)
    return v if v not in (None, "") else default


def _env_num(name: str, default: _T, cast: Callable[[str], _T]) -> _T:
    raw = _env(name)
    if raw is None:
        return default
    try:
        return cast(raw)
    except ValueError as exc:
        raise RuntimeError(f"Invalid value for {name}: {raw!r}") from exc


SSH_HOST = _env("SSH_HOST")
SSH_PORT = _env_num("SSH_PORT", 22, int)
SSH_USER = _env("SSH_USER")
SSH_KEY_PATH = os.path.expanduser(_env("SSH_KEY_PATH", "") or "")
SSH_KEY_PASSPHRASE = _env("SSH_KEY_PASSPHRASE")
SSH_KNOWN_HOSTS = os.path.expanduser(_env("SSH_KNOWN_HOSTS", "") or "")
SSH_CONNECT_TIMEOUT = _env_num("SSH_CONNECT_TIMEOUT", 10, int)

ZEEK_LOG_PATH = (_env("ZEEK_LOG_PATH", "/var/spool/zeek/zeek") or "").rstrip("/")

DEFAULT_LIMIT = _env_num("DEFAULT_LIMIT", 100, int)
MAX_LIMIT = _env_num("MAX_LIMIT", 10_000, int)
if DEFAULT_LIMIT > MAX_LIMIT:
    raise RuntimeError(f"DEFAULT_LIMIT ({DEFAULT_LIMIT}) exceeds MAX_LIMIT ({MAX_LIMIT})")
TAIL_BYTES = _env_num("TAIL_BYTES", 524_288, int)
MAX_TAIL_BYTES = _env_num("MAX_TAIL_BYTES", 8 * 1024 * 1024, int)
STATUS_CACHE_TTL = _env_num("STATUS_CACHE_TTL", 5.0, float)
LOG_CACHE_TTL = _env_num("LOG_CACHE_TTL", 2.0, float)

ALLOWED_ORIGINS = [o.strip() for o in (_env("ALLOWED_ORIGINS", "") or "").split(",") if o.strip()]

DB_PATH = _env("DB_PATH", "") or ""
INGEST_ENABLED = (_env("INGEST_ENABLED", "true") or "").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
)
INGEST_INTERVAL = _env_num("INGEST_INTERVAL", 30.0, float)
INGEST_TAIL_BYTES = _env_num("INGEST_TAIL_BYTES", 2 * 1024 * 1024, int)
RETENTION_ROWS = _env_num("RETENTION_ROWS", 500_000, int)

DEFAULT_KNOWN_LOGS = "conn,dns,http,ssl,ssh,dhcp,notice,files"
KNOWN_LOGS = [
    n.strip() for n in (_env("KNOWN_LOGS", DEFAULT_KNOWN_LOGS) or "").split(",") if n.strip()
]

LOG_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")

FIELD_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]{0,63}$")

# Fields whose Zeek type is set[...] or vector[...].
DEFAULT_SET_FIELDS = (
    "answers,TTLs,msg_types,tunnel_parents,uids,cert_chain_fps,"
    "client_cert_chain_fps,proxied,orig_fuids,resp_fuids,orig_filenames,"
    "resp_filenames,tx_hosts,rx_hosts,fuids,actions,resp_mime_types,"
    "orig_mime_types,parents,sub,sip_proxy_status_code"
)
SET_FIELDS = frozenset(
    n.strip() for n in (_env("ZEEK_SET_FIELDS", DEFAULT_SET_FIELDS) or "").split(",") if n.strip()
)


logger = logging.getLogger("zeek_peek")
if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(_handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False


class SSHError(Exception):
    """Raised when an SSH operation fails. Message is safe to surface."""


_ssh_lock = threading.Lock()
_ssh_client: paramiko.SSHClient | None = None
_sftp_client: paramiko.SFTPClient | None = None
_conn_fail_until = 0.0


def _build_client() -> paramiko.SSHClient:
    host = SSH_HOST
    user = SSH_USER
    if not host or not user:
        raise SSHError("SSH_HOST and SSH_USER must be set")
    client = paramiko.SSHClient()

    # Host key handling.
    if SSH_KNOWN_HOSTS:
        kh_path = Path(SSH_KNOWN_HOSTS)
        if not kh_path.exists():
            raise SSHError(
                f"SSH_KNOWN_HOSTS={SSH_KNOWN_HOSTS} does not exist; "
                "run `ssh-keyscan -H <host>` to create it."
            )
        client.load_host_keys(str(kh_path))
    else:
        with suppress(OSError):
            client.load_system_host_keys()

    client.set_missing_host_key_policy(paramiko.RejectPolicy())

    pkey = None
    if SSH_KEY_PATH:
        key_path = Path(SSH_KEY_PATH)
        if key_path.exists():
            pw_required = False
            for loader in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
                try:
                    pkey = loader.from_private_key_file(str(key_path), password=SSH_KEY_PASSPHRASE)
                    break
                except paramiko.PasswordRequiredException:
                    pw_required = True
                    continue
                except paramiko.SSHException:
                    continue
            if pkey is None and pw_required:
                raise SSHError(
                    "SSH key is encrypted; set SSH_KEY_PASSPHRASE or load it into ssh-agent."
                )

    try:
        client.connect(
            hostname=host,
            port=SSH_PORT,
            username=user,
            pkey=pkey,
            timeout=SSH_CONNECT_TIMEOUT,
            banner_timeout=SSH_CONNECT_TIMEOUT,
            auth_timeout=SSH_CONNECT_TIMEOUT,
            allow_agent=True,
            look_for_keys=False,
        )
    except paramiko.AuthenticationException as exc:
        raise SSHError(
            "SSH authentication failed. Load the key into ssh-agent "
            "(`ssh-add <key>`) or set SSH_KEY_PASSPHRASE."
        ) from exc
    except paramiko.SSHException as exc:
        raise SSHError(f"SSH connection failed: {exc}") from exc
    except OSError as exc:
        raise SSHError(f"Network error connecting to {host}: {exc}") from exc
    return client


def _get_clients() -> tuple[paramiko.SSHClient, paramiko.SFTPClient]:
    """Return (ssh, sftp), reusing existing clients when alive. Caller holds _ssh_lock."""
    global _ssh_client, _sftp_client, _conn_fail_until
    if _ssh_client is not None:
        transport = _ssh_client.get_transport()
        if transport is not None and transport.is_active() and _sftp_client is not None:
            return _ssh_client, _sftp_client
        _close_clients()

    # Fail fast for a short window after a failed connect (a dead host would
    # otherwise make every request wait out the full connect timeout under the lock).
    if time.time() < _conn_fail_until:
        raise SSHError("SSH host recently unreachable; backing off")
    try:
        ssh = _build_client()
        sftp = ssh.open_sftp()
    except Exception:
        _conn_fail_until = time.time() + min(SSH_CONNECT_TIMEOUT, 5)
        raise
    _conn_fail_until = 0.0
    _ssh_client = ssh
    _sftp_client = sftp
    return ssh, sftp


def _close_clients() -> None:
    global _ssh_client, _sftp_client
    for c in (_sftp_client, _ssh_client):
        try:
            if c is not None:
                c.close()
        except Exception as exc:
            logger.debug("Ignoring SSH client close failure: %s", exc)
    _ssh_client = None
    _sftp_client = None


def _safe_remote_path(log_name: str) -> str:
    if not LOG_NAME_RE.match(log_name):
        raise SSHError(f"Invalid log name: {log_name!r}")
    return f"{ZEEK_LOG_PATH}/{log_name}.log"


def ssh_list_logs() -> list[str]:
    """List `*.log` filenames in the Zeek log directory, via SFTP."""
    with _ssh_lock:
        try:
            _, sftp = _get_clients()
            names = sftp.listdir(ZEEK_LOG_PATH)
        except SSHError:
            raise
        except Exception as exc:
            _close_clients()
            raise SSHError(f"Failed to list {ZEEK_LOG_PATH}: {exc}") from exc
    return sorted(n[:-4] for n in names if n.endswith(".log") and not n.startswith("."))


def ssh_fetch_log_blob(log_name: str, tail_bytes: int) -> tuple[str, str, int]:
    """Return (header_text, body_text, file_size) for a Zeek log via SFTP only.

    Reads only the last `tail_bytes` when the file grows past that.
    """
    remote_path = _safe_remote_path(log_name)
    tail_bytes = max(1, min(tail_bytes, MAX_TAIL_BYTES))
    with _ssh_lock:
        try:
            _, sftp = _get_clients()
            try:
                st = sftp.stat(remote_path)
            except FileNotFoundError:
                raise
            except OSError as exc:
                if "No such file" in str(exc):
                    raise FileNotFoundError(remote_path) from exc
                raise
            size = int(st.st_size or 0)
            with sftp.open(remote_path, "rb") as fh:
                fh.seek(0)
                header_bytes = fh.read(min(4096, size))
                if size > tail_bytes:
                    start = size - tail_bytes
                    fh.seek(start - 1)
                    previous_byte = fh.read(1)
                    fh.seek(start)
                    body_bytes = fh.read(tail_bytes)
                    # If the tail window starts mid-line, drop that partial row.
                    if previous_byte != b"\n":
                        nl = body_bytes.find(b"\n")
                        body_bytes = body_bytes[nl + 1 :] if nl >= 0 else b""
                else:
                    fh.seek(0)
                    body_bytes = fh.read(size)
        except FileNotFoundError:
            raise
        except SSHError:
            raise
        except Exception as exc:
            _close_clients()
            raise SSHError(f"Failed to read {remote_path}: {exc}") from exc

    header_text = header_bytes.decode("utf-8", errors="replace")
    body_text = body_bytes.decode("utf-8", errors="replace")
    return header_text, body_text, size


def ssh_fetch_log_delta(log_name: str, from_offset: int) -> tuple[str, str, int]:
    """Return (header_text, body_text, file_size) reading bytes [from_offset, size).

    If the file shrank since `from_offset` (log rotation), reads from byte 0.
    """
    remote_path = _safe_remote_path(log_name)
    with _ssh_lock:
        try:
            _, sftp = _get_clients()
            try:
                st = sftp.stat(remote_path)
            except FileNotFoundError:
                raise
            except OSError as exc:
                if "No such file" in str(exc):
                    raise FileNotFoundError(remote_path) from exc
                raise
            size = int(st.st_size or 0)
            with sftp.open(remote_path, "rb") as fh:
                fh.seek(0)
                header_bytes = fh.read(min(4096, size))
                start = from_offset if 0 < from_offset <= size else 0
                if start >= size:
                    body_bytes = b""
                elif start == 0:
                    fh.seek(0)
                    body_bytes = fh.read(size)
                else:
                    # Drop a partial leading row if `start` isn't on a line boundary.
                    fh.seek(start - 1)
                    previous_byte = fh.read(1)
                    fh.seek(start)
                    body_bytes = fh.read(size - start)
                    if previous_byte != b"\n":
                        nl = body_bytes.find(b"\n")
                        body_bytes = body_bytes[nl + 1 :] if nl >= 0 else b""
        except FileNotFoundError:
            raise
        except SSHError:
            raise
        except Exception as exc:
            _close_clients()
            raise SSHError(f"Failed to read {remote_path}: {exc}") from exc

    return (
        header_bytes.decode("utf-8", errors="replace"),
        body_bytes.decode("utf-8", errors="replace"),
        size,
    )


def parse_zeek(header_text: str, body_text: str) -> tuple[list[str], list[dict[str, Any]]]:
    """Parse Zeek TSV. Returns (fields, rows).

    Honors `#fields`, `#unset_field`, `#empty_field`, and `#set_separator`
    directives from the header.
    """
    fields: list[str] = []
    unset = "-"
    empty = "(empty)"
    set_sep = ","

    for raw_line in header_text.splitlines():
        if not raw_line.startswith("#"):
            continue
        parts = raw_line.split("\t")
        key = parts[0]
        if key == "#fields":
            fields = parts[1:]
        elif key == "#unset_field" and len(parts) > 1:
            unset = parts[1]
        elif key == "#empty_field" and len(parts) > 1:
            empty = parts[1]
        elif key == "#set_separator" and len(parts) > 1 and parts[1]:
            set_sep = parts[1]

    if not fields:
        return [], []

    rows: list[dict[str, Any]] = []
    for line in body_text.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) != len(fields):
            continue
        row: dict[str, Any] = {}
        for name, raw in zip(fields, parts, strict=False):
            if raw == unset:
                row[name] = None
            elif name in SET_FIELDS:
                # Empty set/vector stays a list, not a string.
                row[name] = [] if raw in (empty, "") else raw.split(set_sep)
            elif raw == empty:
                row[name] = ""
            else:
                row[name] = raw
        ts = row.get("ts")
        if isinstance(ts, str):
            with suppress(ValueError):
                row["ts"] = float(ts)
        rows.append(row)
    return fields, rows


def _parse_open(header_text: str) -> str | None:
    """Return the Zeek `#open` header value (a per-file fingerprint)."""
    for line in header_text.splitlines():
        if line.startswith("#open"):
            parts = line.split("\t")
            if len(parts) > 1:
                return parts[1]
    return None


# ---------- caching ----------


class _TTLCache:
    """Tiny thread-safe TTL cache."""

    def __init__(self, ttl: float) -> None:
        self._ttl = ttl
        self._lock = threading.Lock()
        self._data: dict[str, tuple[float, Any]] = {}

    def get(self, key: str) -> Any | None:
        if self._ttl <= 0:
            return None
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return None
            expires, value = entry
            if expires < time.time():
                self._data.pop(key, None)
                return None
            return value

    def set(self, key: str, value: Any, ttl: float | None = None) -> None:
        ttl = self._ttl if ttl is None else ttl
        if ttl <= 0:
            return
        with self._lock:
            self._data[key] = (time.time() + ttl, value)


_status_cache = _TTLCache(STATUS_CACHE_TTL)
_log_cache = _TTLCache(LOG_CACHE_TTL)


_db_lock = threading.Lock()
_db: duckdb.DuckDBPyConnection | None = None
_ingest_task: asyncio.Task[None] | None = None


def _table_name(log_name: str) -> str:
    if not LOG_NAME_RE.match(log_name):
        raise ValueError(f"Invalid log name: {log_name!r}")
    return f"log_{log_name}"


def _quote_ident(name: str) -> str:
    if not FIELD_NAME_RE.match(name):
        raise ValueError(f"Invalid SQL identifier: {name!r}")
    return f'"{name}"'


def _get_db() -> duckdb.DuckDBPyConnection:
    """Open the DuckDB connection, creating the metadata table on first use."""
    global _db
    if _db is not None:
        return _db
    with _db_lock:
        if _db is not None:
            return _db
        if not DB_PATH:
            raise RuntimeError("DB_PATH is empty; storage is disabled")
        path = Path(DB_PATH).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        con = duckdb.connect(str(path))
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS _ingest_state (
                log_name   VARCHAR PRIMARY KEY,
                file_size  BIGINT  NOT NULL,
                last_ts    DOUBLE,
                last_open  VARCHAR,
                updated_at TIMESTAMP DEFAULT now()
            )
            """
        )
        _db = con
        return _db


def _close_db() -> None:
    global _db
    with _db_lock:
        if _db is not None:
            with suppress(Exception):
                _db.close()
            _db = None


def _safe_fields(fields: list[str]) -> list[str]:
    """Drop field names that don't match the strict allowlist, and dedupe them."""
    seen: set[str] = set()
    out: list[str] = []
    for f in fields:
        if FIELD_NAME_RE.match(f) and f not in seen:
            seen.add(f)
            out.append(f)
    return out


def _ensure_table(con: duckdb.DuckDBPyConnection, log_name: str, fields: list[str]) -> None:
    """Create or extend the per-log table to cover every Zeek field name.

    All columns are VARCHAR except `ts` (DOUBLE); set/vector fields are JSON strings.
    """
    table = _table_name(log_name)
    quoted_table = _quote_ident(table)
    existing_rows = con.execute(
        "SELECT column_name FROM information_schema.columns WHERE table_name = ?",
        [table],
    ).fetchall()
    existing = {row[0] for row in existing_rows}

    if not existing:
        cols = ['"ts" DOUBLE'] + [f"{_quote_ident(f)} VARCHAR" for f in fields if f != "ts"]
        con.execute(f"CREATE TABLE {quoted_table} ({', '.join(cols)})")
        con.execute(
            f'CREATE INDEX IF NOT EXISTS {_quote_ident(f"{table}_ts_idx")} ON {quoted_table}("ts")'
        )
        return

    for f in fields:
        if f not in existing:
            col_type = "DOUBLE" if f == "ts" else "VARCHAR"
            con.execute(f"ALTER TABLE {quoted_table} ADD COLUMN {_quote_ident(f)} {col_type}")


def _row_for_db(row: dict[str, Any]) -> dict[str, Any]:
    """Coerce a parsed Zeek row into types DuckDB can take through executemany."""
    out: dict[str, Any] = {}
    for k, v in row.items():
        if v is None:
            out[k] = None
        elif k == "ts":
            out[k] = v if isinstance(v, int | float) else None
        elif isinstance(v, list):
            out[k] = json.dumps(v)
        else:
            out[k] = str(v)
    return out


def db_ingest_one(log_name: str) -> int:
    """Pull new rows from `<log_name>.log` into DuckDB. Returns rows inserted."""
    if not LOG_NAME_RE.match(log_name):
        raise ValueError(f"Invalid log name: {log_name!r}")

    con = _get_db()
    with _db_lock:
        prior = con.execute(
            "SELECT file_size, last_open FROM _ingest_state WHERE log_name = ?",
            [log_name],
        ).fetchone()
    last_size = int(prior[0]) if prior else 0
    prior_open = prior[1] if prior else None

    if last_size == 0:
        # First run: only ingest the recent tail.
        header, body, size = ssh_fetch_log_blob(log_name, INGEST_TAIL_BYTES)
        from_offset = max(0, size - INGEST_TAIL_BYTES)
    else:
        header, body, size = ssh_fetch_log_delta(log_name, last_size)
        from_offset = last_size if size >= last_size else 0
        # Detect rotation by #open change, not just size shrink.
        delta_open = _parse_open(header)
        rotated = size < last_size or (
            prior_open is not None and delta_open is not None and delta_open != prior_open
        )
        if rotated and from_offset > 0:
            # Re-read the whole new file from byte 0.
            header, body, size = ssh_fetch_log_delta(log_name, 0)
            from_offset = 0

    cur_open = _parse_open(header)
    if size == last_size and last_size > 0 and cur_open == prior_open:
        return 0

    fields, rows = parse_zeek(header, body)
    fields = _safe_fields(fields)
    if not fields:
        return 0

    inserted = 0
    with _db_lock:
        _ensure_table(con, log_name, fields)
        if rows:
            cols = ", ".join(_quote_ident(f) for f in fields)
            placeholders = ", ".join(["?"] * len(fields))
            params = [tuple(_row_for_db(r).get(f) for f in fields) for r in rows]
            insert_sql = f"INSERT INTO {_quote_ident(_table_name(log_name))} ({cols}) VALUES ({placeholders})"  # nosec B608
            con.executemany(insert_sql, params)
            inserted = len(rows)
            # Cap rows per table so the DB file stabilises instead of growing forever.
            if RETENTION_ROWS > 0:
                qt = _quote_ident(_table_name(log_name))
                con.execute(  # nosec B608
                    f"DELETE FROM {qt} WHERE rowid NOT IN "
                    f"(SELECT rowid FROM {qt} ORDER BY ts DESC NULLS LAST, rowid DESC LIMIT ?)",
                    [RETENTION_ROWS],
                )

        latest_ts = max(
            (r["ts"] for r in rows if isinstance(r.get("ts"), int | float)),
            default=None,
        )
        con.execute(
            """
            INSERT INTO _ingest_state (log_name, file_size, last_ts, last_open, updated_at)
            VALUES (?, ?, ?, ?, now())
            ON CONFLICT (log_name) DO UPDATE SET
                file_size  = EXCLUDED.file_size,
                last_ts    = COALESCE(EXCLUDED.last_ts, _ingest_state.last_ts),
                last_open  = EXCLUDED.last_open,
                updated_at = now()
            """,
            [log_name, size, latest_ts, cur_open],
        )

    logger.info(
        "ingest %s: +%d rows, file_size=%d (offset=%d)",
        log_name,
        inserted,
        size,
        from_offset,
    )
    return inserted


def db_query_log(log_name: str, limit: int) -> tuple[list[str], list[dict[str, Any]]] | None:
    """Read the newest `limit` rows from DuckDB. Returns None if the table doesn't exist."""
    if not DB_PATH:
        return None
    if not LOG_NAME_RE.match(log_name):
        raise ValueError(f"Invalid log name: {log_name!r}")
    try:
        con = _get_db()
    except Exception:
        return None
    table = _table_name(log_name)
    quoted_table = _quote_ident(table)
    with _db_lock:
        exists = con.execute(
            "SELECT 1 FROM information_schema.tables WHERE table_name = ?", [table]
        ).fetchone()
        if not exists:
            return None
        cols = [
            r[0]
            for r in con.execute(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = ? ORDER BY ordinal_position",
                [table],
            ).fetchall()
        ]
        if not cols:
            return None
        sql = f"SELECT * FROM {quoted_table} ORDER BY ts DESC NULLS LAST, rowid DESC LIMIT ?"  # nosec B608
        raw = con.execute(sql, [limit]).fetchall()

    if not raw:
        return cols, []

    rows: list[dict[str, Any]] = []
    for tup in reversed(raw):  # client expects oldest first
        d: dict[str, Any] = {}
        for col, val in zip(cols, tup, strict=True):
            if val is None:
                d[col] = None
            elif col in SET_FIELDS and isinstance(val, str) and val.startswith("["):
                with suppress(json.JSONDecodeError):
                    d[col] = json.loads(val)
                    continue
                d[col] = val
            else:
                d[col] = val
        rows.append(d)
    return cols, rows


def _db_status() -> dict[str, Any]:
    """Snapshot of the storage layer for /api/status."""
    if not DB_PATH:
        return {"enabled": False}
    info: dict[str, Any] = {
        "enabled": True,
        "path": DB_PATH,
        "ingest_enabled": INGEST_ENABLED,
        "ingest_interval": INGEST_INTERVAL,
    }
    try:
        con = _get_db()
        with _db_lock:
            rows = con.execute(
                "SELECT log_name, file_size, last_ts, updated_at FROM _ingest_state"
            ).fetchall()
        info["state"] = [
            {"log": r[0], "file_size": r[1], "last_ts": r[2], "updated_at": str(r[3])} for r in rows
        ]
    except Exception:
        logger.exception("Failed to collect DB status")
        info["error"] = "Database status unavailable"
    return info


async def _ingest_loop(stop: asyncio.Event) -> None:
    """Background worker that pulls deltas from each known log into DuckDB."""
    logger.info("ingest worker starting (interval=%.0fs)", INGEST_INTERVAL)
    while not stop.is_set():
        for name in KNOWN_LOGS:
            if stop.is_set():
                break
            try:
                await asyncio.to_thread(db_ingest_one, name)
            except FileNotFoundError:
                continue
            except SSHError as exc:
                logger.warning("ingest %s: ssh error: %s", name, exc)
            except Exception:
                logger.exception("ingest %s: unexpected error", name)
        # Interruptible sleep: wake immediately on shutdown.
        with suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=INGEST_INTERVAL)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _ingest_task
    bind_host = _env("HOST", "127.0.0.1")
    if bind_host not in ("127.0.0.1", "localhost", "::1"):
        logger.warning(
            "Bound to %s with no authentication; put zeek-peek behind a reverse "
            "proxy or restrict at the network layer.",
            bind_host,
        )
    stop = asyncio.Event()
    if INGEST_ENABLED and DB_PATH:
        _ingest_task = asyncio.create_task(_ingest_loop(stop))
    yield
    stop.set()
    if _ingest_task is not None:
        # Wait for the in-flight ingest to finish before closing connections.
        with suppress(Exception):
            await _ingest_task
    with _ssh_lock:
        _close_clients()
    _close_db()


app = FastAPI(title="zeek-peek", lifespan=lifespan)

if ALLOWED_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_methods=["GET"],
        allow_headers=["*"],
    )


@app.middleware("http")
async def _security_headers(  # pyright: ignore[reportUnusedFunction]
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    )
    return response


@app.get("/api/health")
def api_health() -> dict[str, Any]:
    return {"ok": True}


@app.get("/api/status")
async def api_status() -> JSONResponse:
    cached = _status_cache.get("status")
    if cached is not None:
        return JSONResponse(cached)

    info: dict[str, Any] = {
        "host": f"{SSH_USER or '?'}@{SSH_HOST or '?'}:{SSH_PORT}",
        "log_path": ZEEK_LOG_PATH,
        "known_logs": KNOWN_LOGS,
        "db": _db_status(),
    }
    started = time.perf_counter()
    try:
        available = await asyncio.to_thread(ssh_list_logs)
        info.update(
            ok=True,
            latency_ms=int((time.perf_counter() - started) * 1000),
            available_logs=available,
        )
    except SSHError as exc:
        info.update(ok=False, error=str(exc))
    except Exception as exc:
        logger.exception("Unexpected error in /api/status")
        info.update(ok=False, error=f"Unexpected error: {exc.__class__.__name__}")

    # Cache failures only briefly.
    _status_cache.set("status", info, ttl=None if info["ok"] else min(STATUS_CACHE_TTL, 1.0))
    return JSONResponse(info)


@app.get("/api/log/{name}")
async def api_log(
    name: str,
    limit: int = Query(default=DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
) -> JSONResponse:
    if not LOG_NAME_RE.match(name):
        raise HTTPException(400, "Invalid log name")

    # Serve from DuckDB when enabled; fall back to SFTP on cold start.
    if DB_PATH:
        try:
            db_result = await asyncio.to_thread(db_query_log, name, limit)
        except Exception:
            logger.exception("DB query failed for %s, falling back to SSH", name)
            db_result = None
        if db_result is not None and db_result[1]:
            db_fields, db_rows = db_result
            return JSONResponse(
                {
                    "name": name,
                    "fields": db_fields,
                    "rows": db_rows,
                    "count": len(db_rows),
                    "missing": False,
                    "source": "db",
                }
            )

    cached: CachedLog | None = _log_cache.get(name)
    if cached is None:
        try:
            header, body, size = await asyncio.to_thread(ssh_fetch_log_blob, name, TAIL_BYTES)
        except FileNotFoundError:
            return JSONResponse(
                {
                    "name": name,
                    "fields": [],
                    "rows": [],
                    "missing": True,
                    "count": 0,
                    "source": "ssh",
                }
            )
        except SSHError as exc:
            raise HTTPException(502, str(exc)) from exc
        except Exception as exc:
            logger.exception("Unexpected error fetching log %s", name)
            raise HTTPException(500, "Internal error") from exc

        parsed_fields, parsed_rows = parse_zeek(header, body)
        cached = CachedLog(fields=parsed_fields, rows=parsed_rows, size=size)
        _log_cache.set(name, cached)

    fields: list[str] = cached["fields"]
    rows: list[dict[str, Any]] = list(cached["rows"])

    if len(rows) > limit:
        rows = rows[-limit:]

    return JSONResponse(
        {
            "name": name,
            "fields": fields,
            "rows": rows,
            "count": len(rows),
            "missing": False,
            "file_size": cached["size"],
            "source": "ssh",
        }
    )


@app.get("/")
def index() -> FileResponse:
    return FileResponse(Path(__file__).parent / "index.html")
