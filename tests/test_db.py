"""Tests for the DuckDB ingest/query layer. SSH layer is monkey-patched."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

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

    fields, rows = db_main.db_query_log("conn", limit=10, since=None)
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

    _, rows = db_main.db_query_log("conn", limit=10, since=None)
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

    _, rows = db_main.db_query_log("conn", limit=10, since=None)
    assert sorted(r["uid"] for r in rows) == ["u1", "u2"]


def test_query_with_since_and_limit(db_main, monkeypatch):
    body = "\n".join(
        [
            "1.0\tu1\thttp\t-",
            "2.0\tu2\tssl\t-",
            "3.0\tu3\tdns\t-",
        ]
    )
    monkeypatch.setattr(db_main, "ssh_fetch_log_blob", lambda n, t: _fake_log_blob(body))
    db_main.db_ingest_one("conn")

    _, rows = db_main.db_query_log("conn", limit=2, since=None)
    assert [r["uid"] for r in rows] == ["u2", "u3"]

    _, rows = db_main.db_query_log("conn", limit=10, since=2.0)
    assert [r["uid"] for r in rows] == ["u2", "u3"]


def test_missing_table_returns_none(db_main):
    # A log we never ingested has no table yet.
    assert db_main.db_query_log("never_ingested", limit=10, since=None) is None


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

    fields, rows = db_main.db_query_log("conn", limit=10, since=None)
    assert "new_col" in fields
    assert rows[-1]["new_col"] == "hello"
    assert rows[0]["new_col"] is None  # backfilled NULL on the first row
