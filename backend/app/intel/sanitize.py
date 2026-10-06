"""Sanitization of untrusted ingested text (dark-web mentions, feed descriptions).

Ingested text is *data*: it is never executed, evaluated or interpolated into
queries. Before NLP or storage it is normalized so that evasion tricks
(zero-width splitting, fullwidth digits, bidi overrides) don't hide entities,
and terminal/log control sequences are neutralized.

All entity spans reported by the NLP pipeline refer to the *sanitized* text,
which is returned alongside them.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

MAX_TEXT_CHARS = 100_000

# Zero-width and bidirectional formatting characters used to split or disguise tokens.
# Built from code points so the source stays plain ASCII.
_INVISIBLE_RANGES = [
    (0x00AD, 0x00AD),  # soft hyphen
    (0x200B, 0x200F),  # zero-width space/joiners, LRM/RLM
    (0x202A, 0x202E),  # bidi embeddings/overrides
    (0x2060, 0x2064),  # word joiner, invisible operators
    (0x2066, 0x2069),  # bidi isolates
    (0xFEFF, 0xFEFF),  # BOM / zero-width no-break space
]
_INVISIBLE = re.compile(
    "[" + "".join(f"{re.escape(chr(a))}-{re.escape(chr(b))}" for a, b in _INVISIBLE_RANGES) + "]"
)
# ANSI escape sequences (CSI ... final byte) and other C0/C1 controls except \t \n.
_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


@dataclass(frozen=True)
class SanitizedText:
    text: str
    truncated: bool
    removed: int  # characters dropped (invisible/control)


def sanitize_text(raw: str, max_chars: int = MAX_TEXT_CHARS) -> SanitizedText:
    text = unicodedata.normalize("NFKC", raw)
    before = len(text)
    text = _ANSI.sub("", text)
    text = _INVISIBLE.sub("", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _CONTROL.sub(" ", text)
    removed = before - len(text)
    truncated = len(text) > max_chars
    return SanitizedText(text=text[:max_chars], truncated=truncated, removed=removed)


def excerpt(text: str, limit: int = 2000) -> str:
    """Sanitized, length-capped text safe to store as a STIX description."""
    clean = sanitize_text(text, max_chars=limit).text
    return clean if len(clean) < limit else clean[: limit - 1] + "…"
