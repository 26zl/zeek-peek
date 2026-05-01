"""Tests for SFTP range-reading behavior. Network calls are faked."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault("SSH_HOST", "test.invalid")
os.environ.setdefault("SSH_USER", "test")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import main


class FakeSFTPFile:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def __enter__(self) -> FakeSFTPFile:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def seek(self, pos: int) -> None:
        self.pos = pos

    def read(self, n: int = -1) -> bytes:
        end = len(self.data) if n < 0 else min(len(self.data), self.pos + n)
        chunk = self.data[self.pos : end]
        self.pos = end
        return chunk


class FakeSFTP:
    def __init__(self, data: bytes) -> None:
        self.data = data

    def stat(self, path: str) -> SimpleNamespace:
        return SimpleNamespace(st_size=len(self.data))

    def open(self, path: str, mode: str) -> FakeSFTPFile:
        return FakeSFTPFile(self.data)


def test_delta_fetch_keeps_first_new_line(monkeypatch):
    header = "#fields\tts\tuid\n"
    row1 = "1.0\tu1\n"
    row2 = "2.0\tu2\n"
    data = (header + row1 + row2).encode()
    from_offset = len((header + row1).encode())

    monkeypatch.setattr(main, "ZEEK_LOG_PATH", "/logs")
    monkeypatch.setattr(main, "_get_clients", lambda: (object(), FakeSFTP(data)))

    _, body, size = main.ssh_fetch_log_delta("conn", from_offset)

    assert size == len(data)
    assert body == row2


def test_tail_fetch_keeps_row_when_window_starts_on_line_boundary(monkeypatch):
    header = "#fields\tts\tuid\n"
    row1 = "1.0\tu1\n"
    row2 = "2.0\tu2\n"
    data = (header + row1 + row2).encode()

    monkeypatch.setattr(main, "ZEEK_LOG_PATH", "/logs")
    monkeypatch.setattr(main, "_get_clients", lambda: (object(), FakeSFTP(data)))

    _, body, size = main.ssh_fetch_log_blob("conn", len(row2.encode()))

    assert size == len(data)
    assert body == row2


def test_tail_fetch_drops_partial_first_row(monkeypatch):
    header = "#fields\tts\tuid\n"
    row1 = "1.0\tu1\n"
    row2 = "2.0\tu2\n"
    data = (header + row1 + row2).encode()

    monkeypatch.setattr(main, "ZEEK_LOG_PATH", "/logs")
    monkeypatch.setattr(main, "_get_clients", lambda: (object(), FakeSFTP(data)))

    _, body, size = main.ssh_fetch_log_blob("conn", len(row2.encode()) + 3)

    assert size == len(data)
    assert body == row2
