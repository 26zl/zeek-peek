"""Tests for the SSH client-building layer; paramiko is monkey-patched."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import paramiko
import pytest

os.environ.setdefault("SSH_HOST", "test.invalid")
os.environ.setdefault("SSH_USER", "test")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import main


class _FakeClient:
    """Stand-in for paramiko.SSHClient; connect() raises whatever we inject."""

    def __init__(self, exc: Exception | None) -> None:
        self._exc = exc

    def load_host_keys(self, path: str) -> None:  # pragma: no cover - trivial
        pass

    def load_system_host_keys(self) -> None:  # pragma: no cover - trivial
        pass

    def set_missing_host_key_policy(self, policy: object) -> None:  # pragma: no cover
        pass

    def connect(self, **kwargs: object) -> None:
        if self._exc is not None:
            raise self._exc


@pytest.mark.parametrize(
    ("exc", "needle"),
    [
        (paramiko.AuthenticationException("bad"), "authentication failed"),
        (paramiko.SSHException("proto"), "connection failed"),
        (OSError("no route"), "network error"),
    ],
)
def test_connect_errors_map_to_ssherror(monkeypatch, exc, needle):
    monkeypatch.setattr(main, "SSH_HOST", "h")
    monkeypatch.setattr(main, "SSH_USER", "u")
    monkeypatch.setattr(main, "SSH_KEY_PATH", "")  # skip key loading
    monkeypatch.setattr(main.paramiko, "SSHClient", lambda: _FakeClient(exc))
    with pytest.raises(main.SSHError) as ei:
        main._build_client()
    assert needle in str(ei.value).lower()


def test_missing_host_or_user_raises(monkeypatch):
    monkeypatch.setattr(main, "SSH_HOST", None)
    monkeypatch.setattr(main, "SSH_USER", None)
    with pytest.raises(main.SSHError, match="must be set"):
        main._build_client()


def test_encrypted_key_without_passphrase_raises(monkeypatch, tmp_path):
    key = tmp_path / "id_key"
    key.write_text("encrypted-key-bytes")
    monkeypatch.setattr(main, "SSH_HOST", "h")
    monkeypatch.setattr(main, "SSH_USER", "u")
    monkeypatch.setattr(main, "SSH_KEY_PATH", str(key))
    monkeypatch.setattr(main, "SSH_KEY_PASSPHRASE", None)

    def raise_pw(path, password=None):
        raise paramiko.PasswordRequiredException("encrypted")

    # Every loader reports the wrapped file as encrypted (real OpenSSH behaviour).
    for loader in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        monkeypatch.setattr(loader, "from_private_key_file", raise_pw)
    monkeypatch.setattr(main.paramiko, "SSHClient", lambda: _FakeClient(None))

    with pytest.raises(main.SSHError, match="encrypted"):
        main._build_client()


def test_missing_known_hosts_file_raises(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "SSH_HOST", "h")
    monkeypatch.setattr(main, "SSH_USER", "u")
    monkeypatch.setattr(main, "SSH_KEY_PATH", "")
    monkeypatch.setattr(main, "SSH_KNOWN_HOSTS", str(tmp_path / "nope"))
    monkeypatch.setattr(main.paramiko, "SSHClient", lambda: _FakeClient(None))
    with pytest.raises(main.SSHError, match="does not exist"):
        main._build_client()


def test_get_clients_backs_off_after_failed_connect(monkeypatch):
    monkeypatch.setattr(main, "_ssh_client", None)
    monkeypatch.setattr(main, "_sftp_client", None)
    monkeypatch.setattr(main, "_conn_fail_until", 0.0)

    calls: list[int] = []

    def boom() -> object:
        calls.append(1)
        raise main.SSHError("down")

    monkeypatch.setattr(main, "_build_client", boom)

    with pytest.raises(main.SSHError):
        main._get_clients()
    with pytest.raises(main.SSHError, match="recently unreachable"):
        main._get_clients()
    assert len(calls) == 1  # second call short-circuited without reconnecting
