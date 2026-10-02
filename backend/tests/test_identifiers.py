from __future__ import annotations

import hashlib
import hmac

import pytest

from app.core.identifiers import DeviceIdHasher, normalize_mac, oui

KEY = b"k" * 32


@pytest.mark.parametrize(
    "mac",
    ["AA:BB:CC:DD:EE:FF", "aa-bb-cc-dd-ee-ff", "aabb.ccdd.eeff", " aabbccddeeff "],
)
def test_normalize_mac_formats(mac: str) -> None:
    assert normalize_mac(mac) == "aabbccddeeff"


@pytest.mark.parametrize("mac", ["", "aa:bb:cc", "zz:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff:00"])
def test_normalize_mac_rejects_invalid(mac: str) -> None:
    with pytest.raises(ValueError, match="invalid MAC"):
        normalize_mac(mac)


def test_oui() -> None:
    assert oui("24-0A-C4-12-34-56") == "24:0a:c4"


def test_device_id_is_hmac_not_plain_hash() -> None:
    hasher = DeviceIdHasher(KEY)
    did = hasher.device_id("AA:BB:CC:DD:EE:FF")
    expected = hmac.new(KEY, b"aabbccddeeff", hashlib.sha256).hexdigest()
    assert did == expected
    assert did != hashlib.sha256(b"aabbccddeeff").hexdigest()


def test_device_id_is_stable_across_formats_and_key_dependent() -> None:
    a = DeviceIdHasher(KEY)
    assert a.device_id("AA:BB:CC:DD:EE:FF") == a.device_id("aabb.ccdd.eeff")
    assert a.device_id("AA:BB:CC:DD:EE:FF") != DeviceIdHasher(b"x" * 32).device_id(
        "AA:BB:CC:DD:EE:FF"
    )


def test_matches_and_repr_hides_key() -> None:
    hasher = DeviceIdHasher(KEY)
    did = hasher.device_id("aa:bb:cc:dd:ee:ff")
    assert hasher.matches("AA-BB-CC-DD-EE-FF", did)
    assert not hasher.matches("aa:bb:cc:dd:ee:00", did)
    assert "k" * 32 not in repr(hasher)


def test_short_key_rejected() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        DeviceIdHasher(b"short")
