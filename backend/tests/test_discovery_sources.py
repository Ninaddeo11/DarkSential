from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Deauth, Dot11Disas, RadioTap
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import ARP, Ether

from app.core.config import Settings
from app.core.identifiers import DeviceIdHasher
from app.detect import capabilities
from app.detect.ble import observation_from_advertisement
from app.detect.nmap_scan import ScanTargetError, parse_nmap_xml, plan, scan, validate_targets
from app.detect.passive import PassiveObserver, observation_from_packet
from app.detect.wifi import DeauthAlert, DeauthMonitor
from tests.conftest import FIXTURES, TEST_HMAC_KEY, SettingsFactory

MAC = "24:0a:c4:40:00:04"

# --- nmap ----------------------------------------------------------------------------


def test_parse_nmap_fixture() -> None:
    hosts = parse_nmap_xml((FIXTURES / "events" / "lab-scan.nmap.xml").read_bytes())
    assert len(hosts) == 6  # the "down" host is skipped
    gw = next(h for h in hosts if h.ip == "192.168.50.1")
    assert gw.mac == "50:C7:BF:00:00:01"
    assert gw.hostname == "archer-gw"
    assert [s.key for s in gw.services] == ["53/tcp", "80/tcp", "22/tcp"]  # closed 8443 dropped
    assert gw.services[0].cpe == ["cpe:/a:thekelleys:dnsmasq:2.80"]
    assert gw.host_cpes == ["cpe:/o:tp-link:archer_ax21_firmware:1.1.1"]
    assert gw.attributes["nmap_vendor"] == "TP-Link Technologies"
    plug = next(h for h in hosts if h.ip == "192.168.50.23")
    assert plug.hostname == "plug-deskscript"  # markup stripped


def test_nmap_xml_entity_expansion_blocked() -> None:
    from defusedxml import EntitiesForbidden

    bomb = (
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaaaaaaaa">'
        '<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]><nmaprun>&b;</nmaprun>'
    )
    with pytest.raises(EntitiesForbidden):
        parse_nmap_xml(bomb)


@pytest.mark.parametrize("target", ["8.8.8.8", "192.168.0.0/16", "10.0.0.0/8", "::1", "x;rm -rf"])
def test_scan_targets_confined_to_lab(settings: Settings, target: str) -> None:
    with pytest.raises(ScanTargetError):
        validate_targets(settings, [target])


def test_scan_plan_and_dry_run(make_settings: SettingsFactory) -> None:
    s = make_settings(nmap_enabled=True)  # DRY_RUN still on
    assert validate_targets(s, ["192.168.50.7", "192.168.50.128/25"]) == [
        "192.168.50.7/32",
        "192.168.50.128/25",
    ]
    cmd = plan(s, "ping")
    assert cmd == ["nmap", "-sn", "-n", "-oX", "-", "192.168.50.0/24"]
    result = scan(s, "service")
    assert result.dry_run is True
    assert result.observations == []
    assert "-sV" in result.command


# --- passive ARP / DHCP / mDNS -------------------------------------------------------


def test_arp() -> None:
    pkt = Ether(src=MAC) / ARP(op=2, hwsrc=MAC, psrc="192.168.50.24")
    o = observation_from_packet(pkt)
    assert o is not None
    assert (o.source, o.mac, o.ip) == ("arp", "240ac4400004", "192.168.50.24")
    probe = Ether(src=MAC) / ARP(op=1, hwsrc=MAC, psrc="0.0.0.0")
    assert observation_from_packet(probe) is None


def test_dhcp_request_and_ack() -> None:
    chaddr = bytes.fromhex("240ac4400004") + b"\x00" * 10
    req = (
        Ether(src=MAC)
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(op=1, chaddr=chaddr)
        / DHCP(
            options=[
                ("message-type", "request"),
                ("requested_addr", "192.168.50.24"),
                ("hostname", b"esp32-node"),
                ("vendor_class_id", b"espressif"),
                ("param_req_list", [1, 3, 6, 15]),
                "end",
            ]
        )
    )
    o = observation_from_packet(req)
    assert o is not None
    assert (o.source, o.mac, o.ip, o.hostname) == (
        "dhcp",
        "240ac4400004",
        "192.168.50.24",
        "esp32-node",
    )
    assert o.attributes == {"dhcp_vendor_class": "espressif", "dhcp_prl": "1,3,6,15"}
    ack = (
        Ether()
        / IP()
        / UDP(sport=67, dport=68)
        / BOOTP(op=2, chaddr=chaddr, yiaddr="192.168.50.99")
        / DHCP(options=[("message-type", "ack"), "end"])
    )
    o2 = observation_from_packet(ack)
    assert o2 is not None
    assert o2.ip == "192.168.50.99"


def test_mdns_announcement() -> None:
    answers = DNSRR(
        rrname="_hap._tcp.local.", type="PTR", rdata="Hall Thermostat._hap._tcp.local."
    ) / DNSRR(rrname="thermo-hall.local.", type="A", rdata="192.168.50.22")
    pkt = (
        Ether(src="18:b4:30:20:00:02")
        / IP(src="192.168.50.22", dst="224.0.0.251")
        / UDP(sport=5353, dport=5353)
        / DNS(qr=1, aa=1, an=answers)
    )
    o = observation_from_packet(pkt)
    assert o is not None
    assert o.source == "mdns"
    assert o.hostname == "thermo-hall"
    assert o.ip == "192.168.50.22"
    assert o.attributes["mdns_services"] == ["_hap._tcp.local"]
    query = Ether() / IP() / UDP(sport=5353, dport=5353) / DNS(qr=0)
    assert observation_from_packet(query) is None


def test_irrelevant_and_malformed_packets() -> None:
    assert observation_from_packet(Ether() / IP() / UDP(sport=1234, dport=80)) is None
    got: list[Any] = []
    observer = PassiveObserver(got.append, iface=None)
    observer._handle(Ether(src=MAC) / ARP(op=2, hwsrc=MAC, psrc="192.168.50.24"))
    observer._handle(object())  # garbage must not raise
    assert len(got) == 1
    observer.stop()  # not started: no-op


# --- BLE -----------------------------------------------------------------------------


def test_ble_advertisement() -> None:
    device = SimpleNamespace(address="C0:FF:EE:00:00:01")
    adv = SimpleNamespace(
        local_name="Tile\x1b[31m",
        rssi=-60,
        tx_power=None,
        manufacturer_data={76: b"\x02", 6: b""},
        service_uuids=["feed"],
    )
    o = observation_from_advertisement(device, adv)
    assert (o.source, o.mac, o.hostname) == ("ble", "c0ffee000001", "Tile")
    assert o.attributes == {
        "ble_rssi": -60,
        "ble_manufacturer_ids": [6, 76],
        "ble_service_uuids": ["feed"],
    }
    mac_os = observation_from_advertisement(
        SimpleNamespace(address="5E1F-UUID"),
        SimpleNamespace(
            local_name=None, rssi=None, tx_power=None, manufacturer_data=None, service_uuids=None
        ),
    )
    assert mac_os.mac is None
    assert mac_os.alt_id == "ble:5e1f-uuid"


# --- Wi-Fi deauth --------------------------------------------------------------------


def _deauth(bssid: str, disas: bool = False) -> Any:
    frame = Dot11Disas() if disas else Dot11Deauth(reason=7)
    return (
        RadioTap()
        / Dot11(type=0, subtype=12, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)
        / frame
    )


def test_deauth_monitor_rate_threshold_and_cooldown() -> None:
    now = [0.0]
    alerts: list[DeauthAlert] = []
    monitor = DeauthMonitor(
        DeviceIdHasher(TEST_HMAC_KEY.encode()),
        alerts.append,
        window_seconds=10,
        threshold_per_min=60,
        cooldown_seconds=100,
        clock=lambda: now[0],
    )
    bssid = "a0:b1:c2:d3:e4:f5"
    for i in range(9):  # 9 frames / 10 s = 54/min: below threshold
        now[0] = i
        assert monitor.handle_frame(_deauth(bssid)) is None
    now[0] = 9.5
    alert = monitor.handle_frame(_deauth(bssid, disas=True))
    assert alert is not None
    assert alert.rate_per_min == 60.0
    assert alert.kinds == {"deauth": 9, "disassoc": 1}
    assert alert.bssid_hmac == DeviceIdHasher(TEST_HMAC_KEY.encode()).device_id(bssid)
    now[0] = 9.8
    assert monitor.handle_frame(_deauth(bssid)) is None  # cooldown
    assert alerts == [alert]
    beacon = RadioTap() / Dot11(type=0, subtype=8, addr3=bssid) / Dot11Beacon()
    assert monitor.handle_frame(beacon) is None


def test_deauth_old_frames_expire() -> None:
    now = [0.0]
    monitor = DeauthMonitor(
        DeviceIdHasher(TEST_HMAC_KEY.encode()),
        lambda a: None,
        window_seconds=10,
        threshold_per_min=30,
        clock=lambda: now[0],
    )
    for i in range(4):
        now[0] = i * 20.0  # one frame every 20 s never accumulates in a 10 s window
        assert monitor.handle_frame(_deauth("a0:b1:c2:d3:e4:f5")) is None


# --- capabilities --------------------------------------------------------------------


def test_capabilities_report_defaults(settings: Settings) -> None:
    report = capabilities.report(settings)
    assert set(report) == {"nmap", "passive", "ble", "wifi"}
    assert not any(s.active for s in report.values())  # all disabled / dry-run by default
    assert "DRY_RUN" in report["nmap"].reason or "nmap binary" in report["nmap"].reason
    assert report["wifi"].reason == "DSN_WIFI_MONITOR_IFACE not set"


def test_capabilities_enabled_but_unavailable(
    make_settings: SettingsFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    s = make_settings(
        dry_run=False,
        nmap_enabled=True,
        ble_scan_enabled=True,
        passive_capture_enabled=True,
        wifi_monitor_enabled=True,
        wifi_monitor_iface="wlan0mon",
    )
    monkeypatch.setattr("app.detect.capabilities.shutil.which", lambda _: "/usr/bin/nmap")
    monkeypatch.setattr(capabilities, "is_privileged", lambda: False)
    report = capabilities.report(s)
    assert report["nmap"].active
    assert report["ble"].active
    assert not report["passive"].active
    assert "root" in report["passive"].reason
    assert not report["wifi"].active
    assert capabilities.is_monitor_iface("../../etc") is False
