"""Structured logging with secret redaction.

- JSON lines (one object per record) for machine parsing, or a plain format.
- ``extra=`` fields are emitted as top-level keys.
- Any extra key that looks secret (password, token, key, ...) is masked, and any
  configured secret *value* appearing anywhere in the output is masked.
- Control characters are escaped so untrusted ingested text cannot forge log
  lines (log injection).
"""

from __future__ import annotations

import json
import logging
import re
import sys
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

REDACTED = "***"
_SECRET_KEY = re.compile(r"(pass(word)?|secret|token|api[_-]?key|auth|credential|hmac)", re.I)
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")

# Attributes present on every LogRecord; anything else came from ``extra=``.
# ``color_message`` is uvicorn's ANSI-colored duplicate of ``msg``.
_RESERVED = frozenset(vars(logging.makeLogRecord({}))) | {
    "message",
    "asctime",
    "taskName",
    "color_message",
}


def _escape_control(text: str) -> str:
    return _CONTROL.sub(lambda m: f"\\x{ord(m.group()):02x}", text)


class Redactor:
    """Masks known secret values and secret-looking keys."""

    def __init__(self, secret_values: Iterable[str] = ()) -> None:
        # Longest first so a secret that contains another is fully masked.
        self._values = sorted({v for v in secret_values if len(v) >= 4}, key=len, reverse=True)

    def text(self, value: str) -> str:
        for secret in self._values:
            value = value.replace(secret, REDACTED)
        return value

    def value(self, key: str, value: object) -> object:
        if _SECRET_KEY.search(key):
            return REDACTED
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, dict):
            return {str(k): self.value(str(k), v) for k, v in value.items()}
        if isinstance(value, list | tuple):
            return [self.value(key, v) for v in value]
        return value


class JsonFormatter(logging.Formatter):
    def __init__(self, redactor: Redactor) -> None:
        super().__init__()
        self._redactor = redactor

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": self._redactor.text(record.getMessage()),
        }
        for key, value in vars(record).items():
            if key not in _RESERVED and not key.startswith("_"):
                payload[key] = self._redactor.value(key, value)
        if record.exc_info:
            payload["exc"] = self._redactor.text(self.formatException(record.exc_info))
        return json.dumps(payload, default=str, ensure_ascii=True)


class PlainFormatter(logging.Formatter):
    def __init__(self, redactor: Redactor) -> None:
        super().__init__("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
        self._redactor = redactor

    def format(self, record: logging.LogRecord) -> str:
        line = super().format(record)
        extras = {
            k: self._redactor.value(k, v)
            for k, v in vars(record).items()
            if k not in _RESERVED and not k.startswith("_")
        }
        if extras:
            line = f"{line} {json.dumps(extras, default=str)}"
        return _escape_control(self._redactor.text(line))


def configure_logging(
    level: str = "INFO", *, json_output: bool = True, secret_values: Iterable[str] = ()
) -> None:
    """Install a single redacting handler on the root logger (idempotent)."""
    redactor = Redactor(secret_values)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter(redactor) if json_output else PlainFormatter(redactor))

    root = logging.getLogger()
    for existing in list(root.handlers):
        if getattr(existing, "_dsn_handler", False):
            root.removeHandler(existing)
    handler._dsn_handler = True  # type: ignore[attr-defined]
    root.addHandler(handler)
    root.setLevel(level)

    # Route uvicorn through the same handler.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        uv_logger = logging.getLogger(name)
        uv_logger.handlers.clear()
        uv_logger.propagate = True
