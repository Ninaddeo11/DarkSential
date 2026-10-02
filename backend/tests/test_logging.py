from __future__ import annotations

import json
import logging

import pytest

from app.core.logging import REDACTED, JsonFormatter, PlainFormatter, Redactor, configure_logging

SECRET = "super-secret-value-123"


def _record(msg: str, *args: object, **extra: object) -> logging.LogRecord:
    record = logging.LogRecord("t", logging.INFO, __file__, 1, msg, args, None)
    for key, value in extra.items():
        setattr(record, key, value)
    return record


def test_json_formatter_emits_extras_and_redacts() -> None:
    fmt = JsonFormatter(Redactor([SECRET]))
    line = fmt.format(
        _record(
            "connecting with %s",
            SECRET,
            host="broker",
            password="pw",
            api_key="abc",
            nested={"token": "t", "note": f"has {SECRET}"},
        )
    )
    data = json.loads(line)
    assert data["msg"] == f"connecting with {REDACTED}"
    assert data["host"] == "broker"
    assert data["password"] == REDACTED
    assert data["api_key"] == REDACTED
    assert data["nested"] == {"token": REDACTED, "note": f"has {REDACTED}"}
    assert SECRET not in line


def test_json_formatter_drops_uvicorn_color_message() -> None:
    data = json.loads(JsonFormatter(Redactor()).format(_record("hi", color_message="\x1b[36mhi")))
    assert "color_message" not in data


def test_json_formatter_neutralizes_log_injection() -> None:
    line = JsonFormatter(Redactor()).format(_record("evil\nFAKE LOG LINE"))
    assert "\n" not in line
    assert json.loads(line)["msg"] == "evil\nFAKE LOG LINE"


def test_json_formatter_includes_exception() -> None:
    try:
        raise RuntimeError(f"boom {SECRET}")
    except RuntimeError:
        import sys

        record = _record("failed")
        record.exc_info = sys.exc_info()
    data = json.loads(JsonFormatter(Redactor([SECRET])).format(record))
    assert "RuntimeError" in data["exc"]
    assert SECRET not in data["exc"]


def test_plain_formatter_redacts_and_escapes() -> None:
    fmt = PlainFormatter(Redactor([SECRET]))
    line = fmt.format(_record(f"value {SECRET}\r\ninjected", items=["a", SECRET]))
    assert SECRET not in line
    assert "\r" not in line
    assert "\\x0d" in line


def test_redactor_masks_longest_secret_first() -> None:
    r = Redactor(["abcd", "abcdefgh"])
    assert r.text("x abcdefgh y") == f"x {REDACTED} y"


def test_redactor_ignores_trivially_short_values() -> None:
    assert Redactor(["ab"]).text("about") == "about"


def test_configure_logging_is_idempotent(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("INFO", json_output=True, secret_values=[SECRET])
    configure_logging("INFO", json_output=True, secret_values=[SECRET])
    handlers = [h for h in logging.getLogger().handlers if getattr(h, "_dsn_handler", False)]
    assert len(handlers) == 1
    logging.getLogger("x").info("hello %s", SECRET)
    out = capsys.readouterr().out.strip().splitlines()
    assert len(out) == 1
    assert SECRET not in out[0]
