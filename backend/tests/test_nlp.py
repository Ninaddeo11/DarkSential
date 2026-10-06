from __future__ import annotations

import json
import time

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from app.intel.nlp import EntityExtractor, Gazetteer, GazetteerEntry, iana_tlds
from tests.conftest import FIXTURES, requires_spacy

pytestmark = requires_spacy

GAZ = Gazetteer(
    entries=[
        GazetteerEntry("malware", "Emotet", ("Emotet", "Geodo")),
        GazetteerEntry("malware", "QakBot", ("QakBot", "QBot", "Pinkslipbot")),
        GazetteerEntry(
            "intrusion-set", "Sandworm Team", ("Sandworm Team", "Voodoo Bear", "ELECTRUM")
        ),
        GazetteerEntry("intrusion-set", "APT28", ("APT28", "Fancy Bear", "Group 74", "Team")),
        # Two entries claiming one alias -> ambiguous, dropped.
        GazetteerEntry("malware", "Alpha", ("Shared Alias",)),
        GazetteerEntry("tool", "Beta", ("Shared Alias",)),
        # An alias equal to another entry's canonical name loses to the canonical.
        GazetteerEntry("malware", "Industroyer", ("Industroyer", "Emotet")),
    ],
    technique_ids=frozenset({"T1190", "T1105", "T1110.001", "T1498"}),
)


@pytest.fixture(scope="module")
def extractor() -> EntityExtractor:
    return EntityExtractor(GAZ)


def values(extractor: EntityExtractor, text: str, *types: str) -> list[str]:
    result = extractor.extract(text)
    return [e.value for e in result.entities if not types or e.type in types]


def test_spans_index_sanitized_text(extractor: EntityExtractor) -> None:
    text = "C2 162.243.103[.]246 and CVE-2023-1389 via T1190 by QBot"
    result = extractor.extract(text)
    assert result.entities
    for ent in result.entities:
        assert result.text[ent.start : ent.end] == ent.text


def test_core_entity_types(extractor: EntityExtractor) -> None:
    text = (
        "CVE-2021-44228 hit 203.0.113.9 and 2001:db8:dead:beef::17 from c2.bad-iot.example.org; "
        "md5 5d41402abc4b2a76b9719d911017c592 sha1 " + "a1" * 20 + " sha256 " + "b2" * 32 + ". "
        "Techniques T1110.001, T1498. Sandworm Team (aka Voodoo Bear) used Emotet."
    )
    result = extractor.extract(text)
    got = {(e.type, e.value) for e in result.entities}
    assert ("CVE", "CVE-2021-44228") in got
    assert ("IPV4", "203.0.113.9") in got
    assert ("IPV6", "2001:db8:dead:beef::17") in got
    assert ("DOMAIN", "c2.bad-iot.example.org") in got
    assert ("MD5", "5d41402abc4b2a76b9719d911017c592") in got
    assert ("SHA1", "a1" * 20) in got
    assert ("SHA256", "b2" * 32) in got
    assert ("ATTACK_TECHNIQUE", "T1110.001") in got
    assert ("ATTACK_TECHNIQUE", "T1498") in got
    assert ("THREAT_ACTOR", "Sandworm Team") in got
    alias = next(e for e in result.entities if e.text == "Voodoo Bear")
    assert alias.value == "Sandworm Team"
    assert alias.confidence == 0.75
    assert ("MALWARE", "Emotet") in got


def test_defanged_iocs(extractor: EntityExtractor) -> None:
    result = extractor.extract("hxxp://192.0.2[.]45:8080/x and evil[.]example(.)com and 1.2.3{.}4")
    got = {(e.type, e.value): e for e in result.entities}
    assert got[("IPV4", "192.0.2.45")].defanged
    assert got[("DOMAIN", "evil.example.com")].defanged
    assert got[("DOMAIN", "evil.example.com")].confidence == 0.9
    assert ("IPV4", "1.2.3.4") in got


def test_case_insensitive_names_and_word_boundaries(extractor: EntityExtractor) -> None:
    assert values(extractor, "the qbot crew", "MALWARE") == ["QakBot"]
    assert values(extractor, "qbotnet and emotetic", "MALWARE") == []


def test_alias_rules(extractor: EntityExtractor) -> None:
    assert values(extractor, "Shared Alias seen") == []  # ambiguous
    assert values(extractor, "Team blue", "THREAT_ACTOR") == []  # stopword alias
    assert values(extractor, "Group 74 again", "THREAT_ACTOR") == ["APT28"]  # has digit
    assert values(extractor, "Emotet loader", "MALWARE") == ["Emotet"]  # canonical wins


def test_unknown_technique_lower_confidence(extractor: EntityExtractor) -> None:
    ent = extractor.extract("T9999 observed").entities[0]
    assert ent.type == "ATTACK_TECHNIQUE"
    assert ent.confidence == 0.6
    assert ent.notes


@pytest.mark.parametrize(
    "noise",
    [
        "CVE-1999-0001x is not a CVE",
        "T12345 is not a technique",
        "config.json and update.exe are files",
        "times 12:30:45 and mac aa:bb:cc:dd:ee:ff",
        "999.1.1.1 is not an IP",
        "email me at someone@example.com",
        "hex 5d41402abc4b2a76b9719d911017c5921 is 33 chars",
        "../../etc/passwd",
    ],
)
def test_noise_produces_no_entities(extractor: EntityExtractor, noise: str) -> None:
    assert extractor.extract(noise).entities == []


def test_low_confidence_heuristics(extractor: EntityExtractor) -> None:
    by_text = {
        e.text: e
        for e in extractor.extract(
            "version 1.2.3.4 README.md 10.0.0.5 " + "0" * 32 + " CVE-2090-1234"
        ).entities
    }
    assert by_text["1.2.3.4"].confidence == 0.25
    assert by_text["README.md"].confidence == 0.3
    assert by_text["10.0.0.5"].confidence == 0.5
    assert by_text["0" * 32].confidence == 0.3
    assert by_text["CVE-2090-1234"].confidence == 0.4


def test_adversarial_evasion(extractor: EntityExtractor) -> None:
    zw = chr(0x200B)
    fullwidth = "".join(chr(0xFF00 + ord(c) - 0x20) for c in "CVE-2021-44228")
    endash = "CVE" + chr(0x2013) + "2014" + chr(0x2013) + "8361"
    text = f"CVE{zw}-2014-8361 / {fullwidth} / {endash} \x1b[31m"
    assert values(extractor, text, "CVE") == ["CVE-2014-8361", "CVE-2021-44228", "CVE-2014-8361"]


def test_injection_strings_are_inert(extractor: EntityExtractor) -> None:
    text = "<script>alert(1)</script> '; MATCH (n) DETACH DELETE n // {{7*7}} ${jndi:ldap://x}"
    result = extractor.extract(text)
    assert all(e.type in {"DOMAIN"} for e in result.entities) or result.entities == []


def test_overlaps_prefer_longest() -> None:
    gaz = Gazetteer(
        [GazetteerEntry("malware", "Black Energy", ()), GazetteerEntry("malware", "Black", ())]
    )
    ents = EntityExtractor(gaz).extract("Black Energy returns").entities
    assert [e.value for e in ents] == ["Black Energy"]


def test_fixture_mentions_extract(extractor: EntityExtractor) -> None:
    data = json.loads((FIXTURES / "darkweb/mentions.sample.json").read_text(encoding="utf-8"))
    by_id = {m["id"]: extractor.extract(m["text"]) for m in data["data"]}
    assert {e.value for e in by_id["dw-0001"].entities} >= {
        "CVE-2023-1389",
        "192.0.2.45",
        "c2.bad-iot.example.org",
        "T1190",
        "T1105",
    }
    assert {e.value for e in by_id["dw-0002"].of_type("MALWARE", "THREAT_ACTOR")} == {
        "Emotet",
        "Sandworm Team",
        "QakBot",
    }
    assert by_id["dw-0007"].entities == []


def test_truncation_flag(extractor: EntityExtractor) -> None:
    assert extractor.extract("a " * 60_000).truncated


@pytest.mark.parametrize(
    "payload",
    [
        "1." * 40_000,
        "a." * 40_000 + "!",
        "a-" * 40_000,
        ":" * 80_000,
        "0" * 80_000,
        "CVE-" * 20_000,
        "[.]" * 30_000,
        "T1" * 40_000,
    ],
    ids=["dots", "labels", "hyphens", "colons", "zeros", "cve-prefix", "defang", "t-ids"],
)
def test_no_catastrophic_backtracking(extractor: EntityExtractor, payload: str) -> None:
    start = time.perf_counter()
    extractor.extract(payload)
    assert time.perf_counter() - start < 5.0


def test_long_runs_masked_for_spacy_but_neighbors_kept(extractor: EntityExtractor) -> None:
    text = ":" * 5000 + " Emotet T1190 " + "[.]" * 2000 + " CVE-2021-44228"
    result = extractor.extract(text)
    assert {e.value for e in result.entities} == {"Emotet", "T1190", "CVE-2021-44228"}
    for ent in result.entities:
        assert result.text[ent.start : ent.end] == ent.text


def test_tld_list_loaded() -> None:
    tlds = iana_tlds()
    assert {"com", "org", "zip", "xn--p1ai"} <= tlds
    assert "exe" not in tlds
    assert "json" not in tlds


@settings(max_examples=150, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(st.text(alphabet=st.characters(codec="utf-8"), max_size=300))
def test_fuzz_never_crashes_and_spans_valid(extractor: EntityExtractor, text: str) -> None:
    result = extractor.extract(text)
    previous_end = -1
    for ent in result.entities:
        assert 0 <= ent.start < ent.end <= len(result.text)
        assert result.text[ent.start : ent.end] == ent.text
        assert 0.0 <= ent.confidence <= 1.0
        assert ent.start >= previous_end  # sorted, non-overlapping
        previous_end = ent.end
