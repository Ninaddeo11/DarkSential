"""Dark-web intelligence: adapter interface + generic licensed REST provider.

No crawler. Mentions come from a licensed provider's REST API, configured by
env (URL, auth header/scheme, items path, field map), or from fixtures.

Each mention is untrusted, adversary-authored text. It is sanitized, run
through the NLP extractor, and turned into:
- Indicators for extracted IPs/domains/hashes above ``MIN_ENTITY_CONFIDENCE``,
- Vulnerability stubs for CVE IDs (deterministic IDs merge with KEV/NVD),
- a Report referencing them, carrying technique IDs and threat names so the
  graph can link the report to existing ATT&CK nodes.
No indicates/attributed-to relationships are invented from co-occurrence:
co-mention is recorded as the Report, which is weaker evidence by design.
"""

from __future__ import annotations

from abc import abstractmethod
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from app.feeds.base import Candidate, FeedAdapter, Rejection
from app.intel.nlp import Entity, EntityExtractor
from app.intel.sanitize import excerpt
from app.intel.stix import (
    ObservableType,
    build_indicator,
    build_report,
    build_source_identity,
    build_vulnerability,
    make_observable,
    parse_timestamp,
)

MIN_ENTITY_CONFIDENCE = 0.5
_ENTITY_OBSERVABLE: dict[str, ObservableType] = {
    "IPV4": "ipv4-addr",
    "IPV6": "ipv6-addr",
    "DOMAIN": "domain-name",
    "MD5": "file-md5",
    "SHA1": "file-sha1",
    "SHA256": "file-sha256",
}
_THREAT_TYPES = {"MALWARE", "THREAT_ACTOR", "TOOL", "CAMPAIGN"}


@dataclass(frozen=True)
class Mention:
    id: str
    source: str
    published: datetime | None
    text: str


def _dig(obj: Any, path: str) -> Any:
    for part in path.split(".") if path else []:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(part)
    return obj


class DarkWebAdapter(FeedAdapter):
    """Base class: subclasses provide ``fetch`` and ``mentions``; normalization is shared."""

    name = "darkweb"

    def __init__(self, ctx: Any, extractor_factory: Callable[[], EntityExtractor]) -> None:
        super().__init__(ctx)
        self._extractor_factory = extractor_factory

    @abstractmethod
    def mentions(self, raw: Any) -> Iterable[Mention | Rejection]: ...

    def candidates(self, raw: Any) -> Iterable[Candidate | Rejection]:
        extractor = self._extractor_factory()
        for mention in self.mentions(raw):
            if isinstance(mention, Rejection):
                yield mention
                continue
            yield from self._normalize_mention(mention, extractor)

    def _normalize_mention(
        self, mention: Mention, extractor: EntityExtractor
    ) -> Iterable[Candidate | Rejection]:
        result = extractor.extract(mention.text)
        if not result.text.strip():
            yield Rejection(mention.id, "empty text")
            return
        seen_at = mention.published or self.ctx.clock()
        identity = build_source_identity(mention.source)
        yield identity
        refs = [identity.id]
        techniques: set[str] = set()
        threat_names: set[str] = set()
        for ent in result.entities:
            built = self._object_for(ent, seen_at, mention)
            if isinstance(built, Rejection):
                yield built
            elif built is not None:
                refs.append(built.id)
                yield built
            elif ent.type == "ATTACK_TECHNIQUE" and ent.confidence >= MIN_ENTITY_CONFIDENCE:
                techniques.add(ent.value)
            elif ent.type in _THREAT_TYPES:
                threat_names.add(ent.value)
        yield build_report(
            f"darkweb:{mention.source}:{mention.id}",
            name=f"Dark-web mention {mention.id} ({mention.source})"[:256],
            published=seen_at,
            object_refs=refs,
            source=self.name,
            confidence=self.confidence,
            description=excerpt(result.text, 2000),
            extra={
                "x_dsn_technique_ids": sorted(techniques),
                "x_dsn_threat_names": sorted(threat_names),
                "x_dsn_entities": [
                    e.model_dump(include={"type", "value", "start", "end", "confidence"})
                    for e in result.entities
                ],
                "x_dsn_text_truncated": result.truncated,
            },
        )

    def _object_for(self, ent: Entity, seen_at: datetime, mention: Mention) -> Any:
        if ent.confidence < MIN_ENTITY_CONFIDENCE:
            return None
        conf = self.confidence * ent.confidence
        if ent.type == "CVE":
            try:
                return build_vulnerability(
                    ent.value, source=self.name, confidence=conf, created=seen_at
                )
            except ValueError as exc:
                return Rejection(f"{mention.id}:{ent.value}", str(exc))
        obs_type = _ENTITY_OBSERVABLE.get(ent.type)
        if obs_type is None:
            return None
        try:
            obs = make_observable(obs_type, ent.value)
        except ValueError as exc:
            return Rejection(f"{mention.id}:{ent.value}", str(exc))
        return build_indicator(
            obs,
            source=self.name,
            confidence=conf,
            valid_from=seen_at,
            labels=["darkweb-mention"],
            description=f"Mentioned in {mention.source} post {mention.id}"[:256],
        )


class GenericRestDarkWebAdapter(DarkWebAdapter):
    """Licensed provider exposing mentions as JSON over HTTPS, mapped by config."""

    def fetch(self) -> Any:
        s = self.ctx.settings
        if not s.darkweb_api_url or s.darkweb_api_key is None:
            raise RuntimeError("darkweb: DSN_DARKWEB_API_URL and DSN_DARKWEB_API_KEY required")
        key = s.darkweb_api_key.get_secret_value()
        value = f"{s.darkweb_auth_scheme} {key}".strip() if s.darkweb_auth_scheme else key
        return self._fetcher().fetch_json(s.darkweb_api_url, headers={s.darkweb_auth_header: value})

    def mentions(self, raw: Any) -> Iterable[Mention | Rejection]:
        s = self.ctx.settings
        fields = s.darkweb_field_map
        items = _dig(raw, s.darkweb_items_path)
        if not isinstance(items, list):
            yield Rejection("darkweb", f"items path {s.darkweb_items_path!r} is not a list")
            return
        for item in items:
            mention_id = _dig(item, fields["id"])
            text = _dig(item, fields["text"])
            if mention_id is None or not isinstance(text, str):
                yield Rejection(str(mention_id), "missing id or text")
                continue
            source = _dig(item, fields.get("source", "")) or "unknown-source"
            yield Mention(
                id=str(mention_id)[:128],
                source=str(source)[:128],
                published=parse_timestamp(_dig(item, fields.get("published", ""))),
                text=text,
            )
