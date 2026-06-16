"""CORS wiring is import-time (driven by ALLOWED_ORIGINS), so reload main with
it set. Isolated in its own module to keep the reload from leaking into others."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from fastapi.testclient import TestClient

os.environ.setdefault("SSH_HOST", "test.invalid")
os.environ.setdefault("SSH_USER", "test")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def test_cors_echoes_configured_origin(monkeypatch):
    monkeypatch.setenv("ALLOWED_ORIGINS", "http://dash.example")
    monkeypatch.setenv("DB_PATH", "")
    sys.modules.pop("main", None)
    try:
        import main as m

        monkeypatch.setattr(m, "ssh_list_logs", lambda: [])
        client = TestClient(m.app)
        r = client.get("/api/health", headers={"Origin": "http://dash.example"})
        assert r.headers.get("access-control-allow-origin") == "http://dash.example"
    finally:
        # Force the next importer to get a fresh module with default env.
        sys.modules.pop("main", None)
