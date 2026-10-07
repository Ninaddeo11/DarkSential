from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError
from sqlalchemy import Engine

from app.core.config import Settings
from app.core.db import init_db, make_engine, make_session_factory
from app.core.events import Event, EventBus
from app.core.identifiers import DeviceIdHasher
from app.detect.observations import Observation, Service
from app.detect.registry import (
    ApprovedEntry,
    DeviceRegistry,
    DevicesConfig,
    load_devices_config,
    node_id_for,
)
from tests.conftest import TEST_HMAC_KEY

T0 = datetime(2026, 10, 1, 8, tzinfo=UTC)
MAC = "24:0a:c4:40:00:04"
HASHER = DeviceIdHasher(TEST_HMAC_KEY.encode())


@pytest.fixture
def engine(settings: Settings) -> Iterator[Engine]:
    eng = make_engine(settings.database_url)
    init_db(eng)
    yield eng
    eng.dispose()


def make_registry(
    engine: Engine, cfg: DevicesConfig | None = None, now: datetime = T0
) -> tuple[DeviceRegistry, list[Event]]:
    bus = EventBus()
    events: list[Event] = []
    bus.subscribe(events.append)
    reg = DeviceRegistry(
        make_session_factory(engine), HASHER, cfg or DevicesConfig(), bus, clock=lambda: now
    )
    return reg, events


def obs(**kw: object) -> Observation:
    base: dict[str, object] = {"source": "arp", "ts": T0, "mac": MAC, "ip": "192.168.50.24"}
    base.update(kw)
    return Observation(**base)  # type: ignore[arg-type]


def test_new_device_identity_vendor_and_event(engine: Engine) -> None:
    reg, events = make_registry(engine)
    view = reg.observe(obs())
    assert view is not None
    assert view.identity_hmac == HASHER.device_id(MAC)
    assert MAC not in view.model_dump_json()  # raw MAC never stored or exposed
    assert view.node_id == node_id_for(view.identity_hmac)
    assert view.vendor is not None
    assert "Espressif" in view.vendor
    assert view.oui == "24:0a:c4"
    assert view.trust == "unknown"
    assert [e.type for e in events] == ["DEVICE_CONNECTED"]
    assert events[0].payload["returning"] is False
    # Same device again: no new event, stable node id.
    assert reg.observe(obs(ts=T0 + timedelta(minutes=1))).node_id == view.node_id  # type: ignore[union-attr]
    assert len(events) == 1


def test_profile_merge_cpes_and_profiled_event(engine: Engine) -> None:
    reg, events = make_registry(engine)
    reg.observe(obs(source="dhcp", hostname="esp32-node", attributes={"dhcp_vendor_class": "esp"}))
    view = reg.observe(
        obs(
            source="nmap",
            services=[Service(port=8883, product="Mosquitto", version="2.0.18")],
            host_cpes=["cpe:/o:tp-link:archer_ax21_firmware:1.1.1"],
        )
    )
    assert view is not None
    assert view.hostname == "esp32-node"
    assert view.sources == ["dhcp", "nmap"]
    assert view.attributes["dhcp_vendor_class"] == "esp"
    assert {c["cpe"].split(":")[4] for c in view.cpes} == {"mosquitto", "archer_ax21_firmware"}
    assert [e.type for e in events] == ["DEVICE_CONNECTED", "DEVICE_PROFILED"]
    # Re-observing the same services doesn't re-emit DEVICE_PROFILED.
    reg.observe(
        obs(source="nmap", services=[Service(port=8883, product="Mosquitto", version="2.0.18")])
    )
    assert [e.type for e in events].count("DEVICE_PROFILED") == 1


def test_ip_only_provisional_then_upgraded(engine: Engine) -> None:
    reg, _ = make_registry(engine)
    provisional = reg.observe(Observation(source="traffic", ts=T0, ip="192.168.50.77"))
    assert provisional is not None
    assert provisional.identity_kind == "ip"
    upgraded = reg.observe(obs(ip="192.168.50.77"))
    assert upgraded is not None
    assert upgraded.node_id == provisional.node_id  # stable node id
    assert upgraded.identity_kind == "mac"
    assert upgraded.identity_hmac == HASHER.device_id(MAC)
    assert len(reg.list()) == 1


def test_ip_only_sighting_attaches_to_known_device(engine: Engine) -> None:
    reg, _ = make_registry(engine)
    known = reg.observe(obs())
    sighting = reg.observe(Observation(source="traffic", ts=T0, ip="192.168.50.24"))
    assert sighting is not None
    assert known is not None
    assert sighting.node_id == known.node_id
    assert reg.resolve(ip="192.168.50.24") == known.node_id
    assert reg.resolve(mac=MAC.upper()) == known.node_id
    assert reg.resolve(mac="aa:aa:aa:aa:aa:aa", ip="10.9.9.9") is None


def test_dhcp_reassignment_moves_ip(engine: Engine) -> None:
    reg, _ = make_registry(engine)
    a = reg.observe(obs())
    b = reg.observe(obs(mac="44:19:b6:10:00:01", ip="192.168.50.24"))
    assert a is not None
    assert b is not None
    assert a.node_id != b.node_id
    assert reg.get(a.node_id).ip is None  # type: ignore[union-attr]
    assert reg.get(b.node_id).ip == "192.168.50.24"  # type: ignore[union-attr]


def test_returning_device_reconnect_event(engine: Engine) -> None:
    reg, events = make_registry(engine)
    reg.observe(obs())
    reg.observe(obs(ts=T0 + timedelta(hours=2)))
    assert [e.payload.get("returning") for e in events] == [False, True]


def test_trust_known_after_and_approval(engine: Engine) -> None:
    cfg = DevicesConfig(known_after_hours=1)
    reg, _ = make_registry(engine, cfg, now=T0 + timedelta(hours=2))
    view = reg.observe(obs())
    assert view is not None
    assert view.trust == "unknown"
    assert reg.refresh_trust() == 1
    assert reg.get(view.node_id).trust == "known"  # type: ignore[union-attr]
    assert reg.approve(view.node_id).trust == "approved"
    assert reg.observe(obs(ts=T0 + timedelta(days=9))).trust == "approved"  # type: ignore[union-attr]
    with pytest.raises(KeyError):
        reg.approve("dev-doesnotexist")


def test_allowlist_by_mac_and_hmac(engine: Engine) -> None:
    other = "44:19:b6:10:00:01"
    cfg = DevicesConfig(
        approved=[ApprovedEntry(mac=MAC), ApprovedEntry(hmac=HASHER.device_id(other))]
    )
    reg, _ = make_registry(engine, cfg)
    assert reg.observe(obs()).trust == "approved"  # type: ignore[union-attr]
    assert reg.observe(obs(mac=other, ip="192.168.50.21")).trust == "approved"  # type: ignore[union-attr]


def test_ble_and_alt_identities(engine: Engine) -> None:
    reg, _ = make_registry(engine)
    ble = reg.observe(Observation(source="ble", ts=T0, mac="c0:ff:ee:00:00:01"))
    mac_os = reg.observe(Observation(source="ble", ts=T0, alt_id="ble:1234-uuid"))
    assert ble is not None
    assert mac_os is not None
    assert ble.identity_kind == "ble"
    assert mac_os.identity_hmac == HASHER.keyed("alt", "ble:1234-uuid")
    assert reg.observe(Observation(source="mdns", ts=T0)) is None  # nothing to key on


@pytest.mark.parametrize(
    "entry",
    [{}, {"mac": "aa:bb:cc:dd:ee:ff", "hmac": "a" * 64}, {"mac": "nope"}, {"hmac": "xyz"}],
)
def test_approved_entry_validation(entry: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        ApprovedEntry(**entry)


def test_shipped_devices_config_loads(settings: Settings, tmp_path: Path) -> None:
    cfg = load_devices_config(settings.devices_config_path)
    assert cfg.approved == []
    assert cfg.known_after_hours == 24
    bad = tmp_path / "d.yaml"
    bad.write_text("approved: []\nsurprise: 1\n", encoding="utf-8")
    with pytest.raises(ValidationError, match="surprise"):
        load_devices_config(bad)
