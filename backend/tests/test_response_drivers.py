from __future__ import annotations

import json
import os
import re
import shutil
from collections.abc import Sequence

import pytest

from app.response.drivers import (
    DriverError,
    DryRunDriver,
    IptablesDriver,
    NftablesDriver,
    build_driver,
    nft_ruleset,
)


class FakeNft:
    """Simulates the nft CLI's state for our table."""

    def __init__(self) -> None:
        self.sets: dict[str, set[str]] | None = None  # None = table absent
        self.calls: list[list[str]] = []

    def __call__(self, argv: Sequence[str], stdin: str | None) -> str:
        argv = list(argv)
        self.calls.append(argv)
        if argv[:3] == ["nft", "-f", "-"]:
            assert stdin is not None
            self.sets = {"quarantine_v4": set(), "quarantine_v6": set()}
            for name in self.sets:
                m = re.search(rf"set {name} {{[^}}]*elements = {{ ([^}}]*) }}", stdin)
                if m:
                    self.sets[name] = {e.strip() for e in m.group(1).split(",")}
            return ""
        if self.sets is None:
            raise DriverError("table inet dsn does not exist")
        if argv[1] in {"add", "delete"}:
            set_name, elem = argv[5], argv[6].strip("{} ")
            if argv[1] == "add":
                self.sets[set_name].add(elem)
            elif elem not in self.sets[set_name]:
                raise DriverError("element does not exist")
            else:
                self.sets[set_name].discard(elem)
            return ""
        if argv[1:4] == ["-j", "list", "set"]:
            elems = sorted(self.sets[argv[6]])
            return json.dumps({"nftables": [{"metainfo": {}}, {"set": {"elem": elems}}]})
        raise AssertionError(argv)


def test_dry_run_driver_records_plan() -> None:
    d = DryRunDriver()
    d.ensure_ready(["192.168.50.24"])
    d.quarantine("192.168.50.25")
    d.quarantine("2001:db8::5")
    d.release("192.168.50.24")
    assert d.active() == {"192.168.50.25", "2001:db8::5"}
    assert any("quarantine_v6 { 2001:db8::5 }" in p for p in d.planned)
    assert all(p.startswith("[dry-run]") for p in d.planned)


def test_nft_ruleset_is_atomic_replace() -> None:
    script = nft_ruleset(["192.168.50.24", "2001:db8::5", "192.168.50.24"])
    lines = script.splitlines()
    assert lines[:2] == ["add table inet dsn", "delete table inet dsn"]
    assert "set quarantine_v4 { type ipv4_addr; elements = { 192.168.50.24 }; }" in script
    assert "set quarantine_v6 { type ipv6_addr; elements = { 2001:db8::5 }; }" in script
    assert "type filter hook forward priority -10; policy accept;" in script
    assert "ip daddr @quarantine_v4 drop" in script
    empty = nft_ruleset([])
    assert "elements" not in empty


def test_nftables_driver_lifecycle_and_idempotency() -> None:
    fake = FakeNft()
    d = NftablesDriver(fake)
    assert d.active() == set()  # table missing -> nothing enforced, no crash
    d.ensure_ready(["192.168.50.24"])
    assert d.active() == {"192.168.50.24"}
    d.quarantine("192.168.50.30")
    d.quarantine("192.168.50.30")  # idempotent
    d.quarantine("2001:db8::7")
    assert d.active() == {"192.168.50.24", "192.168.50.30", "2001:db8::7"}
    d.release("192.168.50.30")
    d.release("192.168.50.30")  # idempotent: no failing delete issued
    assert d.active() == {"192.168.50.24", "2001:db8::7"}
    deletes = [c for c in fake.calls if c[1:2] == ["delete"]]
    assert len(deletes) == 1
    assert [
        "nft",
        "add",
        "element",
        "inet",
        "dsn",
        "quarantine_v6",
        "{ 2001:db8::7 }",
    ] in fake.calls


@pytest.mark.parametrize("bad", ["192.168.50.300", "1.2.3.4; nft flush ruleset", "", "dev-1"])
def test_invalid_ip_never_reaches_a_command(bad: str) -> None:
    fake = FakeNft()
    d = NftablesDriver(fake)
    with pytest.raises(ValueError):  # noqa: PT011
        d.quarantine(bad)
    with pytest.raises(ValueError):  # noqa: PT011
        nft_ruleset([bad])
    assert fake.calls == []


class FakeIptables:
    def __init__(self) -> None:
        self.chains: dict[str, dict[str, list[list[str]]]] = {"iptables": {}, "ip6tables": {}}
        self.calls: list[list[str]] = []

    def __call__(self, argv: Sequence[str], stdin: str | None) -> str:
        argv = list(argv)
        self.calls.append(argv)
        binary, op = argv[0], argv[1]
        chains = self.chains[binary]
        if op == "-N":
            if argv[2] in chains:
                raise DriverError("chain exists")
            chains[argv[2]] = []
            return ""
        if op == "-F":
            chains[argv[2]] = []
            return ""
        if op == "-S":
            if argv[2] not in chains:
                raise DriverError("no chain")
            return "\n".join(f"-A {argv[2]} " + " ".join(r) for r in chains[argv[2]])
        chain, rule = argv[2], argv[3:]
        if op == "-I" and rule and rule[0].isdigit():
            rule = rule[1:]
        rules = chains.setdefault(chain, [])
        if op == "-C":
            if rule not in rules:
                raise DriverError("no such rule")
            return ""
        if op in {"-A", "-I"}:
            rules.insert(0 if op == "-I" else len(rules), rule)
            return ""
        if op == "-D":
            rules.remove(rule)
            return ""
        raise AssertionError(argv)


def test_iptables_driver() -> None:
    fake = FakeIptables()
    d = IptablesDriver(fake)
    d.ensure_ready(["192.168.50.24"])
    d.ensure_ready(["192.168.50.24"])  # idempotent: no duplicate jumps or rules
    assert fake.chains["iptables"]["FORWARD"] == [["-j", "DSN-QUARANTINE"]]
    assert (
        fake.chains["iptables"]["DSN-QUARANTINE"].count(["-s", "192.168.50.24", "-j", "DROP"]) == 1
    )
    d.quarantine("2001:db8::9")
    assert d.active() == {"192.168.50.24", "2001:db8::9"}
    d.release("192.168.50.24")
    d.release("192.168.50.24")
    assert d.active() == {"2001:db8::9"}
    assert fake.chains["iptables"]["DSN-QUARANTINE"] == [["-j", "RETURN"]]


def test_build_driver_policy() -> None:
    assert build_driver("nftables", dry_run=True).name == "dryrun"
    assert build_driver("dryrun", dry_run=False).name == "dryrun"
    assert build_driver("nftables", dry_run=False, runner=FakeNft()).name == "nftables"
    assert build_driver("iptables", dry_run=False, runner=FakeIptables()).name == "iptables"
    with pytest.raises(DriverError, match="unknown"):
        build_driver("pf", dry_run=False)
    if shutil.which("nft") is None:
        with pytest.raises(DriverError, match="nft binary not found"):
            build_driver("nftables", dry_run=False)


def test_run_command_errors() -> None:
    from app.response.drivers import run_command

    with pytest.raises(DriverError):
        run_command(["definitely-not-a-real-binary-dsn"])


# --- real nftables (Linux, CAP_NET_ADMIN): python scripts/tasks.py docker-test-nft ----

REAL_NFT = os.environ.get("DSN_TEST_NFT") == "1"


@pytest.mark.nft
@pytest.mark.skipif(not REAL_NFT, reason="set DSN_TEST_NFT=1 on a Linux host with CAP_NET_ADMIN")
def test_real_nftables_roundtrip() -> None:
    from app.response.drivers import run_command

    d = NftablesDriver()
    try:
        d.ensure_ready(["10.66.0.1"])
        d.quarantine("10.66.0.2")
        d.quarantine("10.66.0.2")
        d.quarantine("fd00::2")
        assert d.active() == {"10.66.0.1", "10.66.0.2", "fd00::2"}
        ruleset = run_command(["nft", "list", "table", "inet", "dsn"])
        assert "ip saddr @quarantine_v4 drop" in ruleset
        d.release("10.66.0.1")
        d.release("10.66.0.1")
        d.ensure_ready(["10.66.0.9"])  # atomic replace, re-seeded
        assert d.active() == {"10.66.0.9"}
    finally:
        run_command(["nft", "delete", "table", "inet", "dsn"])
