from __future__ import annotations

import threading
from datetime import UTC, datetime

import pytest

from app.core.events import Event, EventBus
from app.detect.fingerprint import cpe22_to_23, guess_cpes
from app.detect.observations import Observation, Service
from app.detect.oui import is_locally_administered, vendor_for
from app.graph.cpe import Cpe

# --- OUI -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("mac", "vendor"),
    [
        ("24:0A:C4:12:34:56", "Espressif"),
        ("b8:27:eb:00:00:01", "Raspberry Pi"),
        ("44-19-B6-00-00-01", "Hikvision"),
    ],
)
def test_vendor_lookup(mac: str, vendor: str) -> None:
    found = vendor_for(mac)
    assert found is not None
    assert vendor.lower() in found.lower()


def test_locally_administered_has_no_vendor() -> None:
    assert is_locally_administered("02:00:5e:aa:bb:cc")
    assert not is_locally_administered("24:0a:c4:00:00:01")
    assert vendor_for("02:00:5e:aa:bb:cc") is None


@pytest.mark.parametrize(
    ("mac", "vendor"),
    [
        ("00:1b:c5:00:00:42", "Converging Systems"),  # 36-bit MA-S block 001BC5000
        ("00:1b:c5:00:10:42", "OpenRB.com"),  # neighbouring MA-S block 001BC5001
        ("00:55:da:12:34:56", "KoolPOS"),  # 28-bit MA-M block 0055DA1
    ],
)
def test_sub_block_lookup(mac: str, vendor: str) -> None:
    found = vendor_for(mac)
    assert found is not None
    assert vendor in found


# --- fingerprinting ------------------------------------------------------------------


def test_cpe22_conversion_and_escaping() -> None:
    assert cpe22_to_23("cpe:/a:openbsd:openssh:9.2p1") == (
        "cpe:2.3:a:openbsd:openssh:9.2p1:*:*:*:*:*:*:*"
    )
    hik = cpe22_to_23("cpe:/o:hikvision:ds-2cd2026g2-iu%2fsl_firmware")
    assert hik is not None
    assert Cpe.parse(hik).product == "ds-2cd2026g2-iu/sl_firmware"
    assert cpe22_to_23("not a cpe") is None


def test_guess_cpes_prefers_best_per_product() -> None:
    services = [
        Service(
            port=22, product="OpenSSH", version="9.2p1 Debian", cpe=["cpe:/a:openbsd:openssh:9.2p1"]
        ),
        Service(port=8883, product="Mosquitto", version="2.0.18"),
        Service(port=80, product="lighttpd"),
        Service(port=9, product="something unknown"),
    ]
    guesses = guess_cpes(services, ["cpe:/o:tp-link:archer_ax21_firmware:1.1.1"])
    by_product = {g["cpe"].split(":")[4]: g for g in guesses}
    assert by_product["openssh"]["confidence"] == 0.9  # nmap CPE beats the product table
    assert by_product["openssh"]["basis"] == "nmap-cpe"
    assert by_product["mosquitto"]["cpe"].startswith("cpe:2.3:a:eclipse:mosquitto:2.0.18")
    assert by_product["lighttpd"]["confidence"] == 0.4  # no version
    assert by_product["archer_ax21_firmware"]["basis"] == "nmap-os"
    assert all(Cpe.parse(g["cpe"]) for g in guesses)


def test_guess_escapes_hostile_versions() -> None:
    g = guess_cpes([Service(port=80, product="nginx", version="1.2:*:evil")])[0]
    cpe = Cpe.parse(g["cpe"])
    assert cpe.version == "1.2:*:evil"  # stays one escaped component
    assert cpe.product == "nginx"


# --- observations --------------------------------------------------------------------


def test_observation_sanitizes_device_strings() -> None:
    obs = Observation(
        source="dhcp",
        hostname="cam\x1b[31m<img src=x>‮",
        attributes={"dhcp_vendor_class": "udhcp\x00 1.2", "k" * 100: [1, "x\x07"], "n": object()},
    )
    assert obs.hostname == "camimg src=x"
    assert obs.attributes["dhcp_vendor_class"] == "udhcp  1.2"
    assert len(next(k for k in obs.attributes if k.startswith("k"))) == 64
    assert isinstance(obs.attributes["n"], str)


# --- event bus -----------------------------------------------------------------------


def test_bus_publish_subscribe_history_and_isolation() -> None:
    bus = EventBus(history=3)
    got: list[Event] = []
    unsubscribe = bus.subscribe(got.append)

    def broken(_: Event) -> None:
        raise RuntimeError("handler bug")

    bus.subscribe(broken)
    first = bus.emit("DEVICE_CONNECTED", "dev-1", trust="unknown")
    for i in range(4):
        bus.emit("ANOMALY_DETECTED", f"dev-{i}")
    assert len(got) == 5  # broken handler didn't stop delivery
    assert [e.type for e in bus.recent()] == ["ANOMALY_DETECTED"] * 3  # ring buffer
    assert bus.recent(node_id="dev-3")[0].node_id == "dev-3"
    assert all(e.seq > first.seq for e in bus.recent(after_seq=first.seq))
    unsubscribe()
    bus.emit("DEVICE_PROFILED", "dev-x")
    assert len(got) == 5
    assert first.payload == {"trust": "unknown"}
    assert first.ts.tzinfo is UTC


def test_bus_thread_safety() -> None:
    bus = EventBus(history=10_000)
    threads = [
        threading.Thread(target=lambda: [bus.emit("RISK_UPDATED") for _ in range(500)])
        for _ in range(8)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    seqs = [e.seq for e in bus.recent(limit=10_000)]
    assert len(seqs) == 4000
    assert len(set(seqs)) == 4000
    assert datetime.now(UTC) >= bus.recent()[-1].ts
