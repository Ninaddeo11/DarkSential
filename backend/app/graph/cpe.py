"""CPE 2.3 formatted-string parsing and NVD-style version-range matching."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

_FIELDS = (
    "part",
    "vendor",
    "product",
    "version",
    "update",
    "edition",
    "language",
    "sw_edition",
    "target_sw",
    "target_hw",
    "other",
)
_ANY = "*"
_NA = "-"


def _split_unescaped(text: str) -> list[str]:
    """Split on ':' not preceded by a backslash escape."""
    parts: list[str] = []
    buf: list[str] = []
    escaped = False
    for ch in text:
        if escaped:
            buf.append(ch)
            escaped = False
        elif ch == "\\":
            buf.append(ch)
            escaped = True
        elif ch == ":":
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf))
    return parts


def _unescape(value: str) -> str:
    return re.sub(r"\\(.)", r"\1", value)


@dataclass(frozen=True)
class Cpe:
    part: str
    vendor: str
    product: str
    version: str = _ANY
    update: str = _ANY

    @classmethod
    def parse(cls, text: str) -> Cpe:
        if not text.startswith("cpe:2.3:"):
            raise ValueError("expected a CPE 2.3 formatted string (cpe:2.3:...)")
        fields = _split_unescaped(text[len("cpe:2.3:") :])
        if len(fields) != len(_FIELDS):
            raise ValueError(f"CPE must have {len(_FIELDS)} components, got {len(fields)}")
        values = dict(zip(_FIELDS, (_unescape(f).lower() for f in fields), strict=True))
        if values["part"] not in {"a", "o", "h", _ANY}:
            raise ValueError("CPE part must be a, o, h or *")
        if not values["vendor"] or not values["product"]:
            raise ValueError("CPE vendor and product are required")
        return cls(
            part=values["part"],
            vendor=values["vendor"],
            product=values["product"],
            version=values["version"] or _ANY,
            update=values["update"] or _ANY,
        )


def version_key(version: str) -> tuple[tuple[int, int | str], ...]:
    """Tolerant ordering key: numeric runs compare numerically, text lexically.

    ``2.10 > 2.9``; ``1.0 < 1.0.1``; ``1.0b2`` sorts after ``1.0`` (documented
    approximation: pre-release semantics are vendor-specific).
    """
    tokens = re.findall(r"\d+|[a-z]+", version.lower())
    return tuple((0, int(t)) if t.isdigit() else (1, t) for t in tokens)


@dataclass(frozen=True)
class CpeMatchRule:
    """One NVD cpeMatch entry (vulnerable=true)."""

    criteria: str
    version_start_including: str | None = None
    version_start_excluding: str | None = None
    version_end_including: str | None = None
    version_end_excluding: str | None = None

    @classmethod
    def from_props(cls, props: dict[str, Any]) -> CpeMatchRule:
        return cls(
            criteria=str(props["criteria"]),
            version_start_including=props.get("version_start_including"),
            version_start_excluding=props.get("version_start_excluding"),
            version_end_including=props.get("version_end_including"),
            version_end_excluding=props.get("version_end_excluding"),
        )

    @property
    def has_range(self) -> bool:
        return any(
            (
                self.version_start_including,
                self.version_start_excluding,
                self.version_end_including,
                self.version_end_excluding,
            )
        )

    def match(self, target: Cpe) -> str | None:
        """Return "exact" | "range" | "unversioned" | "any-version", or None if no match."""
        rule = Cpe.parse(self.criteria)
        if rule.vendor != target.vendor or rule.product != target.product:
            return None
        if _ANY not in (rule.part, target.part) and rule.part != target.part:
            return None
        if target.version in (_ANY, _NA):
            # Caller doesn't know the version: possible match, lower certainty.
            return "any-version"
        if self.has_range:
            return "range" if self._in_range(target.version) else None
        if rule.version == _ANY:
            return "unversioned"
        if rule.version == _NA:
            return "unversioned"
        return "exact" if version_key(rule.version) == version_key(target.version) else None

    def _in_range(self, version: str) -> bool:
        key = version_key(version)
        if self.version_start_including and key < version_key(self.version_start_including):
            return False
        if self.version_start_excluding and key <= version_key(self.version_start_excluding):
            return False
        if self.version_end_including and key > version_key(self.version_end_including):
            return False
        return not (self.version_end_excluding and key >= version_key(self.version_end_excluding))
