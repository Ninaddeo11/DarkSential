"""Privacy-preserving device identifiers.

MAC addresses are never stored in clear. They are keyed with
HMAC-SHA256(secret, normalized MAC): a plain hash of a 48-bit MAC is trivially
brute-forced (the OUI space is public), while an HMAC is not without the key.
"""

from __future__ import annotations

import hashlib
import hmac
import re

_HEX12 = re.compile(r"^[0-9a-f]{12}$")
_SEPARATORS = re.compile(r"[:\-.\s]")


def normalize_mac(mac: str) -> str:
    """Return a MAC as 12 lowercase hex digits; accepts ``:``, ``-`` and ``.`` forms."""
    compact = _SEPARATORS.sub("", mac.strip().lower())
    if not _HEX12.fullmatch(compact):
        raise ValueError("invalid MAC address")
    return compact


def oui(mac: str) -> str:
    """Return the vendor OUI prefix (first 3 octets) as ``aa:bb:cc``."""
    compact = normalize_mac(mac)
    return ":".join(compact[i : i + 2] for i in range(0, 6, 2))


class DeviceIdHasher:
    """Derives stable, keyed device IDs from MAC addresses."""

    __slots__ = ("_key",)

    def __init__(self, key: bytes) -> None:
        if len(key) < 32:
            raise ValueError("HMAC key must be at least 32 bytes")
        self._key = key

    def __repr__(self) -> str:
        return "DeviceIdHasher(key=***)"

    def device_id(self, mac: str) -> str:
        """HMAC-SHA256 hex digest of the normalized MAC."""
        digest = hmac.new(self._key, normalize_mac(mac).encode("ascii"), hashlib.sha256)
        return digest.hexdigest()

    def keyed(self, namespace: str, value: str) -> str:
        """HMAC of a namespaced non-MAC identifier (e.g. ``ip:192.168.50.7``)."""
        material = f"{namespace}:{value}".encode()
        return hmac.new(self._key, material, hashlib.sha256).hexdigest()

    def matches(self, mac: str, device_id: str) -> bool:
        """Constant-time check that ``mac`` maps to ``device_id``."""
        return hmac.compare_digest(self.device_id(mac), device_id)
