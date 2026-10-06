from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
import stix2

from app.intel.stix import (
    build_indicator,
    build_malware,
    build_relationship,
    build_report,
    build_source_identity,
    build_vulnerability,
    escape_pattern_value,
    make_observable,
    name_key,
    observable_from_host,
    parse_timestamp,
    pattern_for,
    stix_id,
    validate,
)

NOW = datetime(2026, 9, 30, tzinfo=UTC)


@pytest.mark.parametrize(
    ("obs_type", "raw", "expected"),
    [
        ("ipv4-addr", " 203.0.113.10 ", "203.0.113.10"),
        ("ipv6-addr", "2001:DB8:0:0::17", "2001:db8::17"),
        ("domain-name", "C2.Example.ORG.", "c2.example.org"),
        ("url", "http://198.51.100.7/a", "http://198.51.100.7/a"),
        ("file-md5", "5D41402ABC4B2A76B9719D911017C592", "5d41402abc4b2a76b9719d911017c592"),
        ("file-sha1", "a" * 40, "a" * 40),
        ("file-sha256", "B" * 64, "b" * 64),
    ],
)
def test_make_observable_normalizes(obs_type: str, raw: str, expected: str) -> None:
    assert make_observable(obs_type, raw).value == expected  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("obs_type", "raw"),
    [
        ("ipv4-addr", "2001:db8::1"),
        ("ipv6-addr", "10.0.0.1"),
        ("ipv4-addr", "999.1.1.1"),
        ("domain-name", "not a domain"),
        ("domain-name", "-bad-.com"),
        ("url", "javascript-no-scheme"),
        ("url", "http://has space/x"),
        ("file-md5", "xyz"),
        ("file-sha256", "g" * 64),
    ],
)
def test_make_observable_rejects(obs_type: str, raw: str) -> None:
    with pytest.raises(ValueError):  # noqa: PT011 - several messages
        make_observable(obs_type, raw)  # type: ignore[arg-type]


def test_observable_from_host() -> None:
    assert observable_from_host("192.0.2.1").type == "ipv4-addr"
    assert observable_from_host("[2001:db8::1]").type == "ipv6-addr"
    assert observable_from_host("Evil.Example.COM").value == "evil.example.com"


def test_pattern_escaping_blocks_injection() -> None:
    assert escape_pattern_value("a'b\\c") == "a\\'b\\\\c"
    hostile = make_observable("url", "http://x.test/?q='OR'1'='1']\\")
    d = validate(build_indicator(hostile, source="t", confidence=50, valid_from=NOW))
    assert d["pattern"] == "[url:value = 'http://x.test/?q=\\'OR\\'1\\'=\\'1\\']\\\\']"


def test_pattern_shapes() -> None:
    ip = make_observable("ipv4-addr", "203.0.113.10")
    assert pattern_for(ip, 443).startswith("[network-traffic:dst_ref.type = 'ipv4-addr'")
    assert pattern_for(make_observable("file-sha1", "a" * 40)) == (
        "[file:hashes.'SHA-1' = '" + "a" * 40 + "']"
    )


def test_stix2_rejects_malformed_pattern() -> None:
    with pytest.raises(stix2.exceptions.InvalidValueError):
        stix2.v21.Indicator(pattern="[url:value = 'a' OR ]", pattern_type="stix", valid_from=NOW)


def test_deterministic_ids_converge() -> None:
    a = build_vulnerability("cve-2023-1389", source="kev", confidence=95, created=NOW)
    b = build_vulnerability("CVE-2023-1389", source="nvd", confidence=85, created=NOW)
    assert a.id == b.id == stix_id("vulnerability", "CVE-2023-1389")
    m1 = build_malware("QakBot", source="a", confidence=50)
    m2 = build_malware("  qakbot ", source="b", confidence=50)
    assert m1.id == m2.id


def test_indicator_fields() -> None:
    obs = make_observable("domain-name", "c2.example.org")
    d = validate(
        build_indicator(
            obs,
            source="threatfox",
            confidence=150,  # clamped
            valid_from=NOW,
            valid_until=NOW + timedelta(days=1),
            labels=["Mirai", "", "mirai"],
        )
    )
    assert d["confidence"] == 100
    assert d["labels"] == ["mirai"]
    assert d["x_dsn_observables"] == [{"type": "domain-name", "value": "c2.example.org"}]
    assert d["valid_until"].startswith("2026-10-01")


def test_vulnerability_requires_valid_cve() -> None:
    with pytest.raises(ValueError, match="invalid CVE"):
        build_vulnerability("CVE-23-1", source="x", confidence=1, created=NOW)


def test_vulnerability_modified_never_before_created() -> None:
    v = build_vulnerability(
        "CVE-2020-0001",
        source="x",
        confidence=1,
        created=NOW,
        modified=NOW - timedelta(days=5),
    )
    assert v.modified >= v.created


def test_relationship_report_identity_validate() -> None:
    m = build_malware("Mirai", source="t", confidence=60, aliases=["Katana", "Mirai", " "])
    assert list(m.aliases) == ["Mirai", "Katana"]
    ind = build_indicator(
        make_observable("ipv4-addr", "203.0.113.5"), source="t", confidence=60, valid_from=NOW
    )
    rel = validate(build_relationship(ind.id, "indicates", m.id, confidence=60, source="t"))
    assert rel["relationship_type"] == "indicates"
    ident = build_source_identity("Forum Alpha")
    rep = validate(
        build_report(
            "k",
            name="r",
            published=NOW,
            object_refs=[ind.id, ident.id, ind.id],
            source="dw",
            confidence=40,
            extra={"x_dsn_technique_ids": ["T1190"]},
        )
    )
    assert len(rep["object_refs"]) == 2
    assert rep["x_dsn_technique_ids"] == ["T1190"]


def test_validate_rejects_non_21_and_garbage() -> None:
    with pytest.raises(ValueError, match=r"2.1"):
        validate({"type": "malware", "spec_version": "2.0", "id": "malware--x"})
    with pytest.raises(stix2.exceptions.STIXError):
        validate({"type": "malware", "spec_version": "2.1", "id": "malware--not-a-uuid"})


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("2022-06-04 21:24:53", datetime(2022, 6, 4, 21, 24, 53, tzinfo=UTC)),
        ("2026-09-30 14:02:11 UTC", datetime(2026, 9, 30, 14, 2, 11, tzinfo=UTC)),
        ("2026-10-01", datetime(2026, 10, 1, tzinfo=UTC)),
        ("2026-09-30T18:22:00Z", datetime(2026, 9, 30, 18, 22, tzinfo=UTC)),
        ("2021-12-10T10:15:09.143", datetime(2021, 12, 10, 10, 15, 9, 143000, tzinfo=UTC)),
        ("2026-09-30T20:00:00+02:00", datetime(2026, 9, 30, 18, 0, tzinfo=UTC)),
        ("not-a-date", None),
        ("", None),
        (None, None),
        (12345, None),
    ],
)
def test_parse_timestamp(raw: object, expected: datetime | None) -> None:
    assert parse_timestamp(raw) == expected


def test_name_key() -> None:
    assert name_key("  Sandworm\tTeam ") == "sandworm team"
