from __future__ import annotations

import subprocess
import sys
import textwrap
from typing import Any

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP, Ether

from app.behavior.events import TrafficEvent
from app.detect import passive
from app.detect.passive import PassiveObserver


def test_start_registers_link_layers_for_live_decoding() -> None:
    # Regression: with only the app's narrow scapy imports, a live socket couldn't
    # map ARPHRD_ETHER to Ether, so every captured frame came back undecoded and
    # was silently dropped. Fresh interpreter: this test module imports all layers.
    code = textwrap.dedent(
        """
        import scapy.sendrecv
        from scapy.config import conf

        class FakeSniffer:
            def __init__(self, **kw): pass
            def start(self): pass
            def stop(self): pass

        scapy.sendrecv.AsyncSniffer = FakeSniffer
        from app.detect.passive import PassiveObserver
        before = conf.l2types.get(1)
        PassiveObserver(lambda o: None, "eth0", ignore_ips=frozenset()).start()
        after = conf.l2types.get(1)
        print(getattr(before, "__name__", before), getattr(after, "__name__", after))
        """
    )
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True, timeout=60
    )
    assert out.stdout.split()[-1] == "Ether", out.stdout + out.stderr


def _syn(src: str, dst: str, dport: int) -> Any:
    return Ether(src="68:57:2d:10:00:74") / IP(src=src, dst=dst) / TCP(dport=dport, flags="S")


def test_traffic_capture_batches_and_flushes() -> None:
    clock = [0.0]
    batches: list[list[TrafficEvent]] = []
    obs: list[Any] = []
    o = PassiveObserver(obs.append, "eth0", batches.append, clock=lambda: clock[0])
    o._handle(_syn("10.77.1.74", "162.243.103.246", 8080))
    o._handle(_syn("10.77.1.74", "10.77.2.10", 8883))
    assert batches == []  # still within the batch window
    clock[0] = passive.TRAFFIC_BATCH_SECONDS + 0.1
    o._handle(_syn("10.77.1.74", "10.77.2.10", 8883))
    assert len(batches) == 1
    assert [(e.dst_ip, e.dst_port) for e in batches[0]] == [
        ("162.243.103.246", 8080),
        ("10.77.2.10", 8883),
        ("10.77.2.10", 8883),
    ]
    o._handle(_syn("10.77.1.74", "10.77.2.10", 8883))
    o.stop()  # stop() flushes the remainder
    assert len(batches) == 2
    assert len(batches[1]) == 1


def test_traffic_capture_keeps_discovery_and_survives_bad_packets() -> None:
    batches: list[list[TrafficEvent]] = []
    obs: list[Any] = []
    o = PassiveObserver(obs.append, "eth0", batches.append)
    arp = Ether(src="68:57:2d:10:00:74") / ARP(op=1, hwsrc="68:57:2d:10:00:74", psrc="10.77.1.74")
    o._handle(arp)
    o._handle(object())  # not a packet at all: ignored, no exception
    o.flush()
    assert obs
    assert obs[0].ip == "10.77.1.74"
    assert batches == []  # ARP is discovery, not traffic


def test_without_traffic_sink_only_discovery_runs() -> None:
    obs: list[Any] = []
    o = PassiveObserver(obs.append, "eth0")
    o._handle(_syn("10.77.1.74", "162.243.103.246", 8080))
    o.flush()
    assert obs == []


def test_own_addresses_are_never_profiled() -> None:
    batches: list[list[TrafficEvent]] = []
    obs: list[Any] = []
    o = PassiveObserver(obs.append, "eth0", batches.append, ignore_ips=frozenset({"10.77.1.2"}))
    o._handle(_syn("10.77.1.2", "10.77.1.74", 80))  # the gateway's own nmap probe
    gw_arp = Ether(src="fa:50:35:45:b9:cd") / ARP(op=1, hwsrc="fa:50:35:45:b9:cd", psrc="10.77.1.2")
    o._handle(gw_arp)
    o._handle(_syn("10.77.1.74", "10.77.2.10", 8883))
    o.flush()
    assert obs == []
    assert [e.src_ip for b in batches for e in b] == ["10.77.1.74"]
