from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from app.graph.cpe import Cpe, CpeMatchRule, version_key


def test_parse_basic_and_escaped() -> None:
    c = Cpe.parse("cpe:2.3:o:hikvision:ds-2cd2026g2-iu\\/sl_firmware:-:*:*:*:*:*:*:*")
    assert (c.part, c.vendor, c.product, c.version) == (
        "o",
        "hikvision",
        "ds-2cd2026g2-iu/sl_firmware",
        "-",
    )
    escaped_colon = Cpe.parse("cpe:2.3:a:vendor:prod\\:uct:1.0:*:*:*:*:*:*:*")
    assert escaped_colon.product == "prod:uct"


@pytest.mark.parametrize(
    "bad",
    [
        "cpe:/o:old:format",
        "cpe:2.3:o:too:few",
        "cpe:2.3:x:vendor:product:1:*:*:*:*:*:*:*",
        "cpe:2.3:o::product:1:*:*:*:*:*:*:*",
    ],
)
def test_parse_rejects(bad: str) -> None:
    with pytest.raises(ValueError, match="CPE"):
        Cpe.parse(bad)


def test_version_ordering() -> None:
    assert version_key("2.10") > version_key("2.9")
    assert version_key("1.0.1") > version_key("1.0")
    assert version_key("1.0b2") > version_key("1.0")
    assert version_key("4.0(1)") == version_key("4.0.1")


@given(st.lists(st.integers(min_value=0, max_value=999), min_size=1, max_size=4))
def test_version_key_matches_numeric_tuple(parts: list[int]) -> None:
    v = ".".join(map(str, parts))
    assert version_key(v) == tuple((0, p) for p in parts)


TPLINK = "cpe:2.3:o:tp-link:archer_ax21_firmware:*:*:*:*:*:*:*:*"


def _target(version: str, part: str = "o") -> Cpe:
    return Cpe.parse(f"cpe:2.3:{part}:tp-link:archer_ax21_firmware:{version}:*:*:*:*:*:*:*")


def test_range_match() -> None:
    rule = CpeMatchRule(TPLINK, version_end_excluding="1.1.4")
    assert rule.match(_target("1.1.3")) == "range"
    assert rule.match(_target("1.1.4")) is None
    rule2 = CpeMatchRule(TPLINK, version_start_including="1.0", version_end_including="1.2")
    assert rule2.match(_target("1.2")) == "range"
    assert rule2.match(_target("0.9")) is None
    rule3 = CpeMatchRule(TPLINK, version_start_excluding="1.0")
    assert rule3.match(_target("1.0")) is None
    assert rule3.match(_target("1.0.1")) == "range"


def test_exact_unversioned_any_and_mismatch() -> None:
    exact = CpeMatchRule("cpe:2.3:o:tp-link:archer_ax21_firmware:1.1.1:*:*:*:*:*:*:*")
    assert exact.match(_target("1.1.1")) == "exact"
    assert exact.match(_target("1.1.2")) is None
    assert CpeMatchRule(TPLINK).match(_target("9.9")) == "unversioned"
    na = CpeMatchRule("cpe:2.3:o:tp-link:archer_ax21_firmware:-:*:*:*:*:*:*:*")
    assert na.match(_target("1")) == "unversioned"
    assert exact.match(_target("*")) == "any-version"
    assert exact.match(_target("1.1.1", part="h")) is None
    other = Cpe.parse("cpe:2.3:o:tp-link:other_firmware:1:*:*:*:*:*:*:*")
    assert exact.match(other) is None
