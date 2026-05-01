"""Tests for the Zeek TSV parser. No SSH required."""

from __future__ import annotations

import os

# The module reads env at import time. Provide harmless defaults.
os.environ.setdefault("SSH_HOST", "test.invalid")
os.environ.setdefault("SSH_USER", "test")

from main import parse_zeek

HEADER = "\n".join(
    [
        "#separator \\x09",
        "#set_separator\t,",
        "#empty_field\t(empty)",
        "#unset_field\t-",
        "#path\tconn",
        "#open\t2026-05-01-19-00-02",
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tservice\tanswers",
        "#types\ttime\tstring\taddr\tport\tstring\tvector[string]",
    ]
)


def _row(*vals: str) -> str:
    return "\t".join(vals)


def test_basic_row_parsing():
    body = "\n".join(
        [
            _row("1777661990.906423", "abc", "192.168.1.1", "53", "dns", "-"),
        ]
    )
    fields, rows = parse_zeek(HEADER, body)
    assert fields == ["ts", "uid", "id.orig_h", "id.orig_p", "service", "answers"]
    assert len(rows) == 1
    r = rows[0]
    assert r["ts"] == 1777661990.906423
    assert r["uid"] == "abc"
    assert r["service"] == "dns"
    assert r["answers"] is None  # `-` -> None


def test_unset_and_empty_handling():
    body = "\n".join(
        [
            _row("1.0", "u1", "1.1.1.1", "80", "(empty)", "-"),
        ]
    )
    _, rows = parse_zeek(HEADER, body)
    assert rows[0]["service"] == ""
    assert rows[0]["answers"] is None


def test_set_field_split():
    body = _row("1.0", "u1", "1.1.1.1", "80", "http", "1.2.3.4,5.6.7.8")
    _, rows = parse_zeek(HEADER, body)
    assert rows[0]["answers"] == ["1.2.3.4", "5.6.7.8"]


def test_parser_does_not_strip_first_line():
    """The parser is pure; partial-line trimming is the fetcher's job."""
    body = _row("1.0", "u1", "1.1.1.1", "80", "http", "-")
    _, rows = parse_zeek(HEADER, body)
    assert len(rows) == 1
    assert rows[0]["uid"] == "u1"


def test_malformed_row_skipped():
    body = "\n".join(
        [
            _row("1.0", "u1", "1.1.1.1", "80", "http", "-"),
            _row("BAD", "ROW", "WITH", "WRONG", "COUNT"),  # 5 cols, expected 6
            _row("2.0", "u2", "1.1.1.1", "80", "ssl", "-"),
        ]
    )
    _, rows = parse_zeek(HEADER, body)
    assert [r["uid"] for r in rows] == ["u1", "u2"]


def test_no_fields_header():
    fields, rows = parse_zeek("#path\tconn\n", "1\t2\t3\n")
    assert fields == []
    assert rows == []


def test_comment_lines_ignored_in_body():
    body = "\n".join(
        [
            "#close\t2026-05-01-19-00-02",
            _row("1.0", "u1", "1.1.1.1", "80", "http", "-"),
        ]
    )
    _, rows = parse_zeek(HEADER, body)
    assert len(rows) == 1


def test_custom_separators():
    custom_header = "\n".join(
        [
            "#unset_field\tNULL",
            "#empty_field\tEMPTY",
            "#set_separator\t|",
            "#fields\tts\tservice\tanswers",
        ]
    )
    body = _row("1.0", "EMPTY", "a|b|c")
    _, rows = parse_zeek(custom_header, body)
    assert rows[0]["service"] == ""
    # Default SET_FIELDS still apply: `answers` is in the set list.
    assert rows[0]["answers"] == ["a", "b", "c"]


def test_invalid_ts_falls_back_to_string():
    body = _row("not_a_number", "u1", "1.1.1.1", "80", "http", "-")
    _, rows = parse_zeek(HEADER, body)
    assert rows[0]["ts"] == "not_a_number"


def test_empty_body():
    fields, rows = parse_zeek(HEADER, "")
    assert fields  # header was parsed
    assert rows == []
