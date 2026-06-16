"""HTTP-level tests using FastAPI's TestClient. SSH layer is monkey-patched."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("SSH_HOST", "test.invalid")
os.environ.setdefault("SSH_USER", "test")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import main

HEADER = "\n".join(
    [
        "#separator \\x09",
        "#set_separator\t,",
        "#empty_field\t(empty)",
        "#unset_field\t-",
        "#fields\tts\tuid\tservice",
    ]
)
BODY = "\n".join(
    [
        "1.0\tu1\thttp",
        "2.0\tu2\tssl",
        "3.0\tu3\tdns",
    ]
)


@pytest.fixture
def client(monkeypatch):
    # These tests exercise the SSH path; pin DB off so DuckDB doesn't shadow it.
    monkeypatch.setattr(main, "DB_PATH", "")
    monkeypatch.setattr(main, "ssh_list_logs", lambda: ["conn", "dns"])
    monkeypatch.setattr(main, "ssh_fetch_log_blob", lambda name, tail: (HEADER, BODY, len(BODY)))
    main._status_cache._data.clear()
    main._log_cache._data.clear()
    return TestClient(main.app)


def test_status(client):
    r = client.get("/api/status")
    assert r.status_code == 200
    j = r.json()
    assert j["ok"] is True
    assert j["available_logs"] == ["conn", "dns"]
    assert "host" in j


def test_log_endpoint(client):
    r = client.get("/api/log/conn?limit=10")
    assert r.status_code == 200
    j = r.json()
    assert j["count"] == 3
    assert [row["uid"] for row in j["rows"]] == ["u1", "u2", "u3"]


def test_log_limit(client):
    r = client.get("/api/log/conn?limit=2")
    j = r.json()
    assert j["count"] == 2
    # Limit returns the most recent rows.
    assert [row["uid"] for row in j["rows"]] == ["u2", "u3"]


def test_log_invalid_name(client):
    r = client.get("/api/log/foo;bar")
    assert r.status_code == 400


def test_log_missing(client, monkeypatch):
    def raise_not_found(name, tail):
        raise FileNotFoundError(name)

    monkeypatch.setattr(main, "ssh_fetch_log_blob", raise_not_found)
    main._log_cache._data.clear()
    r = client.get("/api/log/http")
    assert r.status_code == 200
    assert r.json()["missing"] is True


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json() == {"ok": True}


def test_security_headers(client):
    r = client.get("/api/health")
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert r.headers.get("x-frame-options") == "DENY"


def test_status_error_when_ssh_fails(client, monkeypatch):
    def raise_ssh():
        raise main.SSHError("boom")

    monkeypatch.setattr(main, "ssh_list_logs", raise_ssh)
    main._status_cache._data.clear()
    j = client.get("/api/status").json()
    assert j["ok"] is False
    assert "boom" in j["error"]


def test_log_db_error_falls_back_to_ssh(client, monkeypatch):
    # Storage enabled, but the DB query blows up: the endpoint must fall back to
    # SFTP rather than 500.
    monkeypatch.setattr(main, "DB_PATH", "/tmp/zeek-peek-test.duckdb")

    def boom(name, limit):
        raise RuntimeError("db locked")

    monkeypatch.setattr(main, "db_query_log", boom)
    main._log_cache._data.clear()
    r = client.get("/api/log/conn?limit=5")
    assert r.status_code == 200
    j = r.json()
    assert j["source"] == "ssh"
    assert j["count"] == 3


def test_log_ssh_error_returns_502(client, monkeypatch):
    def raise_ssh(name, tail):
        raise main.SSHError("ssh dead")

    monkeypatch.setattr(main, "ssh_fetch_log_blob", raise_ssh)
    main._log_cache._data.clear()
    r = client.get("/api/log/conn")
    assert r.status_code == 502
    assert "ssh dead" in r.text
