#!/usr/bin/env python3
"""Rebuild backend/app/detect/data/oui.tsv.gz from the IEEE registry (stdlib only).

Source: Wireshark's weekly export of the IEEE MA-L/MA-M/MA-S registries
(https://www.wireshark.org/download/automated/data/manuf). The IEEE site itself
rejects scripted downloads. Output lines: "<hex prefix>\t<bits>\t<vendor>", where
the prefix is 6, 7 or 9 hex digits for 24-, 28- or 36-bit blocks.

Usage: python scripts/build_oui.py   (the source asks for at most weekly downloads)
"""

from __future__ import annotations

import gzip
import re
import urllib.request
from pathlib import Path

URL = "https://www.wireshark.org/download/automated/data/manuf"
OUT = Path(__file__).resolve().parents[1] / "backend" / "app" / "detect" / "data" / "oui.tsv.gz"
_LINE = re.compile(r"^([0-9A-Fa-f:]+)(?:/(\d+))?\s+\S+\s+(.+)$")


def main() -> None:
    req = urllib.request.Request(URL, headers={"User-Agent": "dsn-oui-builder/0.1"})
    with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310 - fixed https URL
        text = resp.read().decode("utf-8", "replace")
    rows: list[str] = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        m = _LINE.match(line)
        if not m:
            continue
        bits = int(m.group(2) or 24)
        if bits not in (24, 28, 36):
            continue
        hexdigits = m.group(1).replace(":", "").lower()[: bits // 4]
        vendor = re.sub(r"[\t\r\n]", " ", m.group(3)).strip()
        rows.append(f"{hexdigits}\t{bits}\t{vendor}")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    payload = ("# source: IEEE registry via " + URL + "\n" + "\n".join(sorted(rows)) + "\n").encode()
    # mtime=0 keeps the archive byte-identical across rebuilds of the same data.
    OUT.write_bytes(gzip.compress(payload, mtime=0))
    print(f"wrote {len(rows)} prefixes to {OUT}")


if __name__ == "__main__":
    main()
