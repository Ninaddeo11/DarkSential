"""MAC vendor lookup from the IEEE registry (MA-L 24-bit, MA-M 28-bit, MA-S 36-bit).

Data: ``data/oui.tsv.gz`` built by ``scripts/build_oui.py``. Lookups use the
longest matching block. Locally administered addresses (bit 0x02 of the first
octet), as used by MAC randomization and most BLE devices, have no vendor.
"""

from __future__ import annotations

import gzip
from functools import lru_cache
from pathlib import Path

from app.core.identifiers import normalize_mac

_DATA = Path(__file__).with_name("data") / "oui.tsv.gz"


@lru_cache(maxsize=1)
def _table() -> dict[int, dict[str, str]]:
    table: dict[int, dict[str, str]] = {24: {}, 28: {}, 36: {}}
    with gzip.open(_DATA, "rt", encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("#"):
                continue
            prefix, bits, vendor = line.rstrip("\n").split("\t", 2)
            table[int(bits)][prefix] = vendor
    return table


def is_locally_administered(mac: str) -> bool:
    return bool(int(normalize_mac(mac)[:2], 16) & 0x02)


def vendor_for(mac: str) -> str | None:
    compact = normalize_mac(mac)
    if is_locally_administered(compact):
        return None
    table = _table()
    for bits in (36, 28, 24):
        vendor = table[bits].get(compact[: bits // 4])
        if vendor:
            return vendor
    return None
