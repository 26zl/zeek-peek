"""The TrustedHost middleware is wired at import time from ALLOWED_HOSTS."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from fastapi.testclient import TestClient

os.environ.setdefault("SSH_HOST", "test.invalid")
os.environ.setdefault("SSH_USER", "test")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _fresh_main(monkeypatch):
    monkeypatch.setenv("DB_PATH", "")
    sys.modules.pop("main", None)
    import main as m

    monkeypatch.setattr(m, "ssh_list_logs", lambda: [])
    return m


def test_loopback_host_is_allowed(monkeypatch):
    try:
        m = _fresh_main(monkeypatch)
        client = TestClient(m.app, base_url="http://localhost")
        assert client.get("/api/health").status_code == 200
    finally:
        sys.modules.pop("main", None)


def test_rebinding_host_is_rejected(monkeypatch):
    try:
        m = _fresh_main(monkeypatch)
        # A page rebinding its own domain to 127.0.0.1 still sends its own Host.
        client = TestClient(m.app, base_url="http://attacker.example")
        assert client.get("/api/health").status_code == 400
    finally:
        sys.modules.pop("main", None)


def test_allowed_hosts_is_configurable(monkeypatch):
    try:
        monkeypatch.setenv("ALLOWED_HOSTS", "dash.internal")
        m = _fresh_main(monkeypatch)
        allowed = TestClient(m.app, base_url="http://dash.internal")
        assert allowed.get("/api/health").status_code == 200
        # The default loopback host is no longer accepted once overridden.
        rejected = TestClient(m.app, base_url="http://localhost")
        assert rejected.get("/api/health").status_code == 400
    finally:
        sys.modules.pop("main", None)
