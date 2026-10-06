"""Entity extraction from untrusted threat text: spaCy EntityRuler + regex.

Two complementary matchers feed one result list:

* **Regex (character level)** for CVE IDs, IPv4/IPv6, domains and file hashes.
  These don't tokenize well (spaCy splits ``2021-44228`` on the hyphen) and are
  frequently *defanged* (``1.2.3[.]4``, ``evil[.]com``), which a char regex
  handles directly. Every candidate is validated (``ipaddress``, IANA TLD list,
  hash length) before it is reported.
* **spaCy EntityRuler (token level)** for ATT&CK technique IDs (regex token
  pattern) and malware / threat-actor / tool names, seeded from the ATT&CK
  graph via :class:`Gazetteer`. Token matching gives word-boundary-correct,
  case-insensitive name matches.

Overlaps are resolved longest-span-first. Spans index into the *sanitized* text
returned with the result. All regexes are linear-time (bounded quantifiers, no
nested unbounded repetition); tests run them on adversarial inputs.

Confidence is a heuristic score in [0, 1] describing extraction certainty, not
maliciousness. See docs/architecture.md for the table.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel

from app.intel.sanitize import sanitize_text

if TYPE_CHECKING:
    from spacy.language import Language

EntityType = Literal[
    "CVE",
    "IPV4",
    "IPV6",
    "DOMAIN",
    "MD5",
    "SHA1",
    "SHA256",
    "ATTACK_TECHNIQUE",
    "MALWARE",
    "THREAT_ACTOR",
    "TOOL",
    "CAMPAIGN",
]

_TLD_FILE = Path(__file__).with_name("data") / "tlds.txt"
# Real TLDs that are also common file extensions: likely filenames, not domains.
_FILE_LIKE_TLDS = frozenset({"zip", "mov", "py", "sh", "md", "pl", "rs", "sx", "so", "ps"})

_DOT = r"(?:\.|\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\))"
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"

# Hyphen-like dashes seen in pasted text: U+2010, U+2011, U+2013, U+2014.
_DASHES = "".join(chr(c) for c in (0x2010, 0x2011, 0x2013, 0x2014))
_RE_DASH = re.compile(f"[{_DASHES}]")
_RE_CVE = re.compile(rf"(?<![\w-])CVE[-{_DASHES}]\d{{4}}[-{_DASHES}]\d{{4,7}}(?![\w-])", re.I)
_RE_IPV4 = re.compile(rf"(?<![\w.\[]){_OCTET}(?:{_DOT}{_OCTET}){{3}}(?![\w\[]|\.\d)")
_RE_IPV6 = re.compile(r"(?<![\w:.])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![\w:])", re.I)
_RE_DOMAIN = re.compile(
    rf"(?<![\w.@-])(?:{_LABEL}{_DOT}){{1,10}}[a-z]{{2,24}}(?![\w-]|\[\.\])", re.I
)
_RE_HASH = re.compile(r"(?<!\w)(?:[0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})(?!\w)", re.I)
_RE_VERSION_CTX = re.compile(r"(?:version|ver\.?|v|build|release)\s*$", re.I)
_RE_DEFANG = re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.I)
_RE_LONG_RUN = re.compile(r"\S{65,}")

_HASH_TYPES: dict[int, EntityType] = {32: "MD5", 40: "SHA1", 64: "SHA256"}
_ALIAS_MIN_LEN = 4
_ALIAS_STOPWORDS = frozenset({"group", "team", "unknown", "agent", "update", "service", "admin"})


class Entity(BaseModel):
    type: EntityType
    value: str
    text: str
    start: int
    end: int
    confidence: float
    method: Literal["regex", "entity_ruler"]
    defanged: bool = False
    notes: list[str] = []


class ExtractionResult(BaseModel):
    text: str
    truncated: bool
    entities: list[Entity]

    def of_type(self, *types: EntityType) -> list[Entity]:
        return [e for e in self.entities if e.type in types]


@lru_cache(maxsize=1)
def iana_tlds() -> frozenset[str]:
    lines = _TLD_FILE.read_text(encoding="ascii").splitlines()
    return frozenset(line.strip().lower() for line in lines if line and not line.startswith("#"))


def _refang(text: str) -> str:
    return _RE_DEFANG.sub(".", text)


# --- Gazetteer ---------------------------------------------------------------------

_KIND_LABEL: dict[str, EntityType] = {
    "malware": "MALWARE",
    "intrusion-set": "THREAT_ACTOR",
    "tool": "TOOL",
    "campaign": "CAMPAIGN",
}


@dataclass(frozen=True)
class GazetteerEntry:
    kind: str  # STIX type: malware | intrusion-set | tool | campaign
    name: str
    aliases: tuple[str, ...] = ()


@dataclass
class Gazetteer:
    """Known names (seeded from the ATT&CK graph) and technique IDs."""

    entries: list[GazetteerEntry] = field(default_factory=list)
    technique_ids: frozenset[str] = frozenset()

    def surface_forms(self) -> dict[str, tuple[EntityType, str, bool]]:
        """Map casefolded surface form -> (label, canonical name, is_alias).

        Aliases claimed by two different entries are dropped as ambiguous.
        """
        forms: dict[str, tuple[EntityType, str, bool]] = {}
        ambiguous: set[str] = set()
        for entry in self.entries:
            label = _KIND_LABEL.get(entry.kind)
            if label is None:
                continue
            forms[entry.name.casefold()] = (label, entry.name, False)
        for entry in self.entries:
            label = _KIND_LABEL.get(entry.kind)
            if label is None:
                continue
            for alias in entry.aliases:
                key = alias.casefold()
                if key == entry.name.casefold() or not _usable_alias(alias):
                    continue
                existing = forms.get(key)
                if existing and existing[1] != entry.name:
                    if not existing[2]:
                        continue  # a canonical name wins over someone's alias
                    ambiguous.add(key)
                    continue
                forms[key] = (label, entry.name, True)
        for key in ambiguous:
            if forms.get(key, (None, None, False))[2]:
                del forms[key]
        return forms


def _usable_alias(alias: str) -> bool:
    stripped = alias.strip()
    if stripped.casefold() in _ALIAS_STOPWORDS:
        return False
    return len(stripped) >= _ALIAS_MIN_LEN or any(ch.isdigit() for ch in stripped)


# --- Extractor ---------------------------------------------------------------------


class EntityExtractor:
    def __init__(self, gazetteer: Gazetteer | None = None) -> None:
        self._gazetteer = gazetteer or Gazetteer()
        self._forms = self._gazetteer.surface_forms()
        self._nlp = self._build_pipeline()

    def _build_pipeline(self) -> Language:
        import spacy  # lab-only dependency, imported lazily

        nlp = spacy.blank("en")
        ruler = nlp.add_pipe("entity_ruler", config={"validate": True})
        patterns: list[dict[str, object]] = [
            {
                "label": "ATTACK_TECHNIQUE",
                "pattern": [{"TEXT": {"REGEX": r"^T\d{4}(?:\.\d{3})?$"}}],
            }
        ]
        for form, (label, canonical, _) in self._forms.items():
            tokens = [{"LOWER": tok.lower_} for tok in nlp.make_doc(form)]
            if tokens:
                patterns.append({"label": label, "pattern": tokens, "id": canonical})
        ruler.add_patterns(patterns)  # type: ignore[attr-defined]
        return nlp

    def extract(self, raw_text: str) -> ExtractionResult:
        clean = sanitize_text(raw_text)
        text = clean.text
        candidates = [
            *self._regex_entities(text),
            *self._ruler_entities(text),
        ]
        return ExtractionResult(
            text=text, truncated=clean.truncated, entities=_resolve_overlaps(candidates)
        )

    # -- regex ------------------------------------------------------------------

    def _regex_entities(self, text: str) -> Iterable[Entity]:
        yield from _cves(text)
        yield from _ipv4s(text)
        yield from _ipv6s(text)
        yield from _domains(text)
        yield from _hashes(text)

    # -- spaCy ------------------------------------------------------------------

    def _ruler_entities(self, text: str) -> Iterable[Entity]:
        # spaCy's tokenizer is roughly quadratic on long whitespace-free runs
        # (measured: 20k ':' -> 49 s). Names and technique IDs are short tokens, so
        # blank out long runs with same-length padding; offsets stay valid.
        masked = _RE_LONG_RUN.sub(lambda m: " " * len(m.group()), text)
        doc = self._nlp(masked)
        for ent in doc.ents:
            label = ent.label_
            if label == "ATTACK_TECHNIQUE":
                tid = ent.text.upper()
                known = tid in self._gazetteer.technique_ids
                yield Entity(
                    type="ATTACK_TECHNIQUE",
                    value=tid,
                    text=ent.text,
                    start=ent.start_char,
                    end=ent.end_char,
                    confidence=0.95 if known else 0.6,
                    method="entity_ruler",
                    notes=[] if known else ["technique id not in local ATT&CK graph"],
                )
                continue
            form = self._forms.get(ent.text.casefold())
            if form is None:  # pragma: no cover - ruler only matches known forms
                continue
            entity_type, canonical, is_alias = form
            yield Entity(
                type=entity_type,
                value=canonical,
                text=ent.text,
                start=ent.start_char,
                end=ent.end_char,
                confidence=0.75 if is_alias else 0.85,
                method="entity_ruler",
                notes=[f"alias of {canonical}"] if is_alias else [],
            )


def _cves(text: str) -> Iterable[Entity]:
    this_year = datetime.now(UTC).year
    for m in _RE_CVE.finditer(text):
        value = _RE_DASH.sub("-", m.group()).upper()
        year = int(value[4:8])
        plausible = 1999 <= year <= this_year + 1
        yield Entity(
            type="CVE",
            value=value,
            text=m.group(),
            start=m.start(),
            end=m.end(),
            confidence=0.97 if plausible else 0.4,
            method="regex",
            notes=[] if plausible else ["implausible CVE year"],
        )


def _ipv4s(text: str) -> Iterable[Entity]:
    for m in _RE_IPV4.finditer(text):
        raw = m.group()
        value = _refang(raw)
        try:
            ip = ipaddress.IPv4Address(value)
        except ValueError:  # pragma: no cover - regex already bounds octets
            continue
        defanged = raw != value
        notes: list[str] = []
        confidence = 0.95 if defanged else 0.85
        if _RE_VERSION_CTX.search(text[max(0, m.start() - 12) : m.start()]):
            confidence, notes = 0.25, ["looks like a version number"]
        if not ip.is_global:
            confidence = min(confidence, 0.5)
            notes.append("non-global address")
        yield Entity(
            type="IPV4",
            value=ip.compressed,
            text=raw,
            start=m.start(),
            end=m.end(),
            confidence=confidence,
            method="regex",
            defanged=defanged,
            notes=notes,
        )


def _ipv6s(text: str) -> Iterable[Entity]:
    for m in _RE_IPV6.finditer(text):
        raw = m.group()
        if raw.count(":") < 2 or not any(c in "0123456789abcdefABCDEF" for c in raw):
            continue
        try:
            ip = ipaddress.IPv6Address(raw)
        except ValueError:
            continue
        if ip.is_unspecified:
            continue
        notes = [] if ip.is_global else ["non-global address"]
        yield Entity(
            type="IPV6",
            value=ip.compressed,
            text=raw,
            start=m.start(),
            end=m.end(),
            confidence=0.85 if ip.is_global else 0.5,
            method="regex",
            notes=notes,
        )


def _domains(text: str) -> Iterable[Entity]:
    tlds = iana_tlds()
    for m in _RE_DOMAIN.finditer(text):
        raw = m.group()
        value = _refang(raw).lower().rstrip(".")
        tld = value.rsplit(".", 1)[-1]
        if tld not in tlds:
            continue
        defanged = raw.lower() != value
        notes: list[str] = []
        confidence = 0.9 if defanged else 0.7
        if tld in _FILE_LIKE_TLDS and not defanged:
            confidence, notes = 0.3, ["TLD is also a common file extension"]
        yield Entity(
            type="DOMAIN",
            value=value,
            text=raw,
            start=m.start(),
            end=m.end(),
            confidence=confidence,
            method="regex",
            defanged=defanged,
            notes=notes,
        )


def _hashes(text: str) -> Iterable[Entity]:
    for m in _RE_HASH.finditer(text):
        raw = m.group()
        value = raw.lower()
        notes: list[str] = []
        confidence = 0.9
        if len(set(value)) <= 2 or value.isdigit():
            confidence, notes = 0.3, ["low-entropy hex string"]
        yield Entity(
            type=_HASH_TYPES[len(value)],
            value=value,
            text=raw,
            start=m.start(),
            end=m.end(),
            confidence=confidence,
            method="regex",
            notes=notes,
        )


def _resolve_overlaps(candidates: list[Entity]) -> list[Entity]:
    """Keep the longest (then most confident) span among overlapping candidates."""
    chosen: list[Entity] = []
    for ent in sorted(candidates, key=lambda e: (-(e.end - e.start), -e.confidence, e.start)):
        if all(ent.end <= c.start or ent.start >= c.end for c in chosen):
            chosen.append(ent)
    return sorted(chosen, key=lambda e: (e.start, e.end))
