"""Tests for the DuckDB ingest/query layer. SSH layer is monkey-patched."""

from __future__ import annotations

import asyncio
import os
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("SSH_HOST", "test.invalid")
os.environ.setdefault("SSH_USER", "test")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture
def db_main(tmp_path, monkeypatch):
    """Reload main with a temp DB_PATH so each test gets an isolated DuckDB file."""
    monkeypatch.setenv("DB_PATH", str(tmp_path / "test.duckdb"))
    monkeypatch.setenv("INGEST_ENABLED", "false")
    if "main" in sys.modules:
        del sys.modules["main"]
    import main as m

    yield m
    m._close_db()


def _fake_log_blob(rows_text: str):
    header = "\n".join(
        [
            "#separator \\x09",
            "#set_separator\t,",
            "#empty_field\t(empty)",
            "#unset_field\t-",
            "#fields\tts\tuid\tservice\tanswers",
        ]
    )
    return header, rows_text, len(rows_text)


def test_first_ingest_creates_table_and_inserts(db_main, monkeypatch):
    body = "\n".join(
        [
            "1.0\tu1\thttp\ta,b",
            "2.0\tu2\tssl\t-",
        ]
    )
    monkeypatch.setattr(db_main, "ssh_fetch_log_blob", lambda n, t: _fake_log_blob(body))

    inserted = db_main.db_ingest_one("conn")
    assert inserted == 2

    fields, rows = db_main.db_query_log("conn", limit=10)
    assert "uid" in fields and "ts" in fields
    assert [r["uid"] for r in rows] == ["u1", "u2"]
    assert rows[0]["answers"] == ["a", "b"]  # set field decoded back
    assert rows[1]["answers"] is None


def test_delta_ingest_uses_offset(db_main, monkeypatch):
    body1 = "1.0\tu1\thttp\t-\n"
    body2 = "2.0\tu2\tssl\t-\n"

    state = {"size": 0}

    def fake_blob(name, tail):
        state["size"] = len(body1)
        return _fake_log_blob(body1)

    def fake_delta(name, from_offset):
        # Caller has already ingested body1; ingest only the delta.
        full = body1 + body2
        state["size"] = len(full)
        return _fake_log_blob(full)[0], body2, len(full)

    monkeypatch.setattr(db_main, "ssh_fetch_log_blob", fake_blob)
    monkeypatch.setattr(db_main, "ssh_fetch_log_delta", fake_delta)

    assert db_main.db_ingest_one("conn") == 1
    assert db_main.db_ingest_one("conn") == 1

    _, rows = db_main.db_query_log("conn", limit=10)
    assert [r["uid"] for r in rows] == ["u1", "u2"]


def test_delta_ingest_keeps_same_timestamp_rows(db_main, monkeypatch):
    body1 = "1.0\tu1\thttp\t-\n"
    body2 = "1.0\tu2\tssl\t-\n"

    def fake_blob(name, tail):
        return _fake_log_blob(body1)

    def fake_delta(name, from_offset):
        return _fake_log_blob(body1 + body2)[0], body2, len(body1) + len(body2)

    monkeypatch.setattr(db_main, "ssh_fetch_log_blob", fake_blob)
    monkeypatch.setattr(db_main, "ssh_fetch_log_delta", fake_delta)

    assert db_main.db_ingest_one("conn") == 1
    assert db_main.db_ingest_one("conn") == 1

    _, rows = db_main.db_query_log("conn", limit=10)
    assert sorted(r["uid"] for r in rows) == ["u1", "u2"]


def test_query_returns_newest_limit_rows(db_main, monkeypatch):
    body = "\n".join(
        [
            "1.0\tu1\thttp\t-",
            "2.0\tu2\tssl\t-",
            "3.0\tu3\tdns\t-",
        ]
    )
    monkeypatch.setattr(db_main, "ssh_fetch_log_blob", lambda n, t: _fake_log_blob(body))
    db_main.db_ingest_one("conn")

    # Newest `limit` rows, returned oldest-first.
    _, rows = db_main.db_query_log("conn", limit=2)
    assert [r["uid"] for r in rows] == ["u2", "u3"]


def test_missing_table_returns_none(db_main):
    # A log we never ingested has no table yet.
    assert db_main.db_query_log("never_ingested", limit=10) is None


def _hdr(open_ts: str) -> str:
    return "\n".join(
        [
            "#separator \\x09",
            "#set_separator\t,",
            "#empty_field\t(empty)",
            "#unset_field\t-",
            f"#open\t{open_ts}",
            "#fields\tts\tuid\tservice\tanswers",
        ]
    )


def test_rotation_detected_when_new_file_outgrows_old(db_main, monkeypatch):
    # First file (#open A), two rows.
    body1 = "1.0\tu1\thttp\t-\n2.0\tu2\tssl\t-\n"
    monkeypatch.setattr(db_main, "ssh_fetch_log_blob", lambda n, t: (_hdr("A"), body1, len(body1)))
    assert db_main.db_ingest_one("conn") == 2

    # Rotated file (#open B) that has ALREADY grown past the old size between polls.
    # Size-only detection would read mid-file and lose the leading rows; identity
    # (the changed #open) must trigger a full re-read from byte 0.
    new_full = "3.0\tu3\tdns\t-\n4.0\tu4\thttp\t-\n5.0\tu5\tssl\t-\n6.0\tu6\tdns\t-\n"
    assert len(new_full) > len(body1)

    def fake_delta(name, from_offset):
        body = new_full[from_offset:] if from_offset < len(new_full) else ""
        return _hdr("B"), body, len(new_full)

    monkeypatch.setattr(db_main, "ssh_fetch_log_delta", fake_delta)
    db_main.db_ingest_one("conn")

    _, rows = db_main.db_query_log("conn", limit=20)
    uids = [r["uid"] for r in rows]
    # No leading rows of the rotated file were lost.
    assert uids == ["u1", "u2", "u3", "u4", "u5", "u6"]


def test_query_returns_none_when_storage_disabled(db_main, monkeypatch):
    monkeypatch.setattr(db_main, "DB_PATH", "")
    assert db_main.db_query_log("conn", limit=5) is None


def test_db_status_reports_state_after_ingest(db_main, monkeypatch):
    body = "1.0\tu1\thttp\t-\n"
    monkeypatch.setattr(db_main, "ssh_fetch_log_blob", lambda n, t: _fake_log_blob(body))
    db_main.db_ingest_one("conn")

    st = db_main._db_status()
    assert st["enabled"] is True
    assert any(s["log"] == "conn" for s in st["state"])


def test_db_status_disabled_when_no_path(db_main, monkeypatch):
    monkeypatch.setattr(db_main, "DB_PATH", "")
    assert db_main._db_status() == {"enabled": False}


def test_ingest_loop_iterates_logs_survives_errors_and_stops(db_main, monkeypatch):
    seen: list[str] = []

    def fake(name):
        seen.append(name)
        # Hit both the FileNotFoundError (skip) and SSHError (warn) branches.
        if name == "conn":
            raise FileNotFoundError(name)
        raise db_main.SSHError("down")

    monkeypatch.setattr(db_main, "db_ingest_one", fake)
    monkeypatch.setattr(db_main, "KNOWN_LOGS", ["conn", "dns"])
    monkeypatch.setattr(db_main, "INGEST_INTERVAL", 0.001)

    async def run():
        stop = asyncio.Event()
        task = asyncio.create_task(db_main._ingest_loop(stop))
        await asyncio.sleep(0.03)  # let at least one full iteration run
        stop.set()
        await asyncio.wait_for(task, timeout=2)

    asyncio.run(run())
    assert "conn" in seen and "dns" in seen  # loop kept going past the errors


def test_lifespan_starts_and_cleanly_stops_ingest(db_main, monkeypatch):
    ran: list[str] = []
    monkeypatch.setattr(db_main, "INGEST_ENABLED", True)
    monkeypatch.setattr(db_main, "KNOWN_LOGS", ["conn"])
    monkeypatch.setattr(db_main, "INGEST_INTERVAL", 0.001)
    monkeypatch.setattr(db_main, "db_ingest_one", lambda n: ran.append(n))

    # Entering/exiting the context runs lifespan startup and shutdown.
    with TestClient(db_main.app):
        deadline = 50
        while not ran and deadline:
            time.sleep(0.01)
            deadline -= 1
    assert ran  # the worker started and did at least one tick


def test_schema_extension_on_new_field(db_main, monkeypatch):
    body1 = "1.0\tu1\thttp\t-\n"
    monkeypatch.setattr(db_main, "ssh_fetch_log_blob", lambda n, t: _fake_log_blob(body1))
    db_main.db_ingest_one("conn")

    # Second ingest with an extra column should ALTER TABLE, not crash.
    extra_header = "\n".join(
        [
            "#separator \\x09",
            "#set_separator\t,",
            "#empty_field\t(empty)",
            "#unset_field\t-",
            "#fields\tts\tuid\tservice\tanswers\tnew_col",
        ]
    )
    body2 = "2.0\tu2\tssl\t-\thello\n"

    def fake_delta(name, from_offset):
        return extra_header, body2, len(body1) + len(body2)

    monkeypatch.setattr(db_main, "ssh_fetch_log_delta", fake_delta)
    assert db_main.db_ingest_one("conn") == 1

    fields, rows = db_main.db_query_log("conn", limit=10)
    assert "new_col" in fields
    assert rows[-1]["new_col"] == "hello"
    assert rows[0]["new_col"] is None  # backfilled NULL on the first row
