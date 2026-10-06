from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from app.intel.sanitize import excerpt, sanitize_text

ZWSP = chr(0x200B)
RLO = chr(0x202E)
BOM = chr(0xFEFF)


def test_removes_invisible_and_bidi() -> None:
    clean = sanitize_text(f"CVE{ZWSP}-2014-8361 {RLO}evil{BOM}")
    assert clean.text == "CVE-2014-8361 evil"
    assert clean.removed == 3


def test_nfkc_folds_fullwidth() -> None:
    fullwidth = "".join(chr(0xFF00 + ord(c) - 0x20) for c in "CVE-2021-44228")
    assert sanitize_text(fullwidth).text == "CVE-2021-44228"


def test_strips_ansi_and_controls_keeps_newlines() -> None:
    clean = sanitize_text("a\x1b[31mRED\x1b[0m\x00b\r\nc\td")
    assert clean.text == "aRED b\nc\td"


def test_truncates() -> None:
    clean = sanitize_text("x" * 50, max_chars=10)
    assert clean.text == "x" * 10
    assert clean.truncated


def test_excerpt() -> None:
    assert excerpt("short") == "short"
    long = excerpt("y" * 100, limit=10)
    assert len(long) == 10
    assert long.endswith("…")


@given(st.text(max_size=500))
def test_sanitized_output_has_no_dangerous_chars(raw: str) -> None:
    out = sanitize_text(raw).text
    assert "\x1b" not in out
    assert ZWSP not in out
    assert RLO not in out
    assert all(c in "\n\t" or ord(c) >= 0x20 for c in out)
    assert not any(0x7F <= ord(c) <= 0x9F for c in out)
