"""Enforcement drivers: nftables (preferred), iptables, dry-run.

Contract (``ResponseDriver``): idempotent ``quarantine(ip)`` / ``release(ip)``,
``active()`` returning the IPs currently enforced (for startup reconciliation),
and ``ensure_ready(desired)`` that (re)creates the driver's own ruleset.

Safety:
* Every IP is parsed with ``ipaddress`` before it reaches a command. Commands are
  argument lists, never shell strings.
* Drivers touch only their own objects: the ``inet dsn`` table, or the
  ``DSN-QUARANTINE`` chain. They never flush or reorder anything else.
* ``DRY_RUN=true`` always selects the dry-run driver, whatever is configured.

nftables model (one atomic transaction via ``nft -f -``)::

    table inet dsn {
      set quarantine_v4 { type ipv4_addr; }
      set quarantine_v6 { type ipv6_addr; }
      chain forward { type filter hook forward priority -10; policy accept;
        ip saddr @quarantine_v4 drop;  ip daddr @quarantine_v4 drop
        ip6 saddr @quarantine_v6 drop; ip6 daddr @quarantine_v6 drop }
      chain input   { type filter hook input priority -10; policy accept;
        ip saddr @quarantine_v4 drop;  ip6 saddr @quarantine_v6 drop }
    }

Adding/removing a set element is a single atomic command, so traffic is never
half-blocked. ``ensure_ready`` replaces the whole table atomically
(add-delete-define in one transaction), seeded with the desired elements, so
reconciliation can't leave a window where quarantined devices are free.
"""

from __future__ import annotations

import contextlib
import ipaddress
import json
import logging
import shutil
import subprocess
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Protocol

log = logging.getLogger(__name__)

Runner = Callable[[Sequence[str], str | None], str]
TABLE = "dsn"
CHAIN = "DSN-QUARANTINE"


class DriverError(RuntimeError):
    pass


def run_command(argv: Sequence[str], stdin: str | None = None) -> str:
    """Execute a command without a shell. Raises DriverError with stderr on failure."""
    try:
        done = subprocess.run(  # noqa: S603 - argv list, no shell; IPs pre-validated
            list(argv), input=stdin, capture_output=True, text=True, timeout=15, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DriverError(f"{argv[0]}: {type(exc).__name__}") from exc
    if done.returncode != 0:
        raise DriverError(f"{' '.join(argv[:3])}: {done.stderr.strip()[:300]}")
    return done.stdout


def parse_ip(ip: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    return ipaddress.ip_address(ip.strip())


class ResponseDriver(Protocol):
    name: str

    def ensure_ready(self, desired: Iterable[str]) -> None: ...

    def quarantine(self, ip: str) -> None: ...

    def release(self, ip: str) -> None: ...

    def active(self) -> set[str]: ...


@dataclass
class DryRunDriver:
    """Enforces nothing; records the nftables commands it would run."""

    name: str = "dryrun"
    planned: list[str] = field(default_factory=list)
    _active: set[str] = field(default_factory=set)

    def ensure_ready(self, desired: Iterable[str]) -> None:
        self._active = {parse_ip(ip).compressed for ip in desired}
        self.planned.append(
            f"[dry-run] nft -f - (replace table inet {TABLE}, {len(self._active)} elements)"
        )

    def quarantine(self, ip: str) -> None:
        addr = parse_ip(ip)
        self._active.add(addr.compressed)
        self.planned.append(
            f"[dry-run] nft add element inet {TABLE} {_set_for(addr)} {{ {addr.compressed} }}"
        )
        log.warning("DRY_RUN: quarantine not enforced", extra={"ip": addr.compressed})

    def release(self, ip: str) -> None:
        addr = parse_ip(ip)
        self._active.discard(addr.compressed)
        self.planned.append(
            f"[dry-run] nft delete element inet {TABLE} {_set_for(addr)} {{ {addr.compressed} }}"
        )

    def active(self) -> set[str]:
        return set(self._active)


def _set_for(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    return "quarantine_v4" if addr.version == 4 else "quarantine_v6"


def nft_ruleset(desired: Iterable[str]) -> str:
    v4 = sorted({parse_ip(i).compressed for i in desired if parse_ip(i).version == 4})
    v6 = sorted({parse_ip(i).compressed for i in desired if parse_ip(i).version == 6})

    def elements(items: list[str]) -> str:
        return f" elements = {{ {', '.join(items)} }};" if items else ""

    # add + delete + define in ONE transaction = atomic replace (works when absent).
    return f"""add table inet {TABLE}
delete table inet {TABLE}
table inet {TABLE} {{
  set quarantine_v4 {{ type ipv4_addr;{elements(v4)} }}
  set quarantine_v6 {{ type ipv6_addr;{elements(v6)} }}
  chain forward {{
    type filter hook forward priority -10; policy accept;
    ip saddr @quarantine_v4 drop
    ip daddr @quarantine_v4 drop
    ip6 saddr @quarantine_v6 drop
    ip6 daddr @quarantine_v6 drop
  }}
  chain input {{
    type filter hook input priority -10; policy accept;
    ip saddr @quarantine_v4 drop
    ip6 saddr @quarantine_v6 drop
  }}
}}
"""


@dataclass
class NftablesDriver:
    runner: Runner = run_command
    name: str = "nftables"

    def ensure_ready(self, desired: Iterable[str]) -> None:
        self.runner(["nft", "-f", "-"], nft_ruleset(desired))

    def quarantine(self, ip: str) -> None:
        addr = parse_ip(ip)
        # Adding an existing element is a no-op in nftables: idempotent.
        self.runner(
            ["nft", "add", "element", "inet", TABLE, _set_for(addr), f"{{ {addr.compressed} }}"],
            None,
        )

    def release(self, ip: str) -> None:
        addr = parse_ip(ip)
        if addr.compressed not in self.active():
            return  # idempotent: deleting a missing element would error
        self.runner(
            ["nft", "delete", "element", "inet", TABLE, _set_for(addr), f"{{ {addr.compressed} }}"],
            None,
        )

    def active(self) -> set[str]:
        found: set[str] = set()
        for set_name in ("quarantine_v4", "quarantine_v6"):
            try:
                out = self.runner(["nft", "-j", "list", "set", "inet", TABLE, set_name], None)
            except DriverError:
                continue  # table not created yet
            for item in json.loads(out).get("nftables", []):
                for elem in item.get("set", {}).get("elem", []) or []:
                    if isinstance(elem, str):
                        found.add(parse_ip(elem).compressed)
        return found


@dataclass
class IptablesDriver:
    """Fallback for hosts without nftables. Per-IP rules in a dedicated chain.

    Not atomic across the two directions (src rule, then dst rule): prefer nftables.
    """

    runner: Runner = run_command
    name: str = "iptables"

    def _bin(self, addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
        return "iptables" if addr.version == 4 else "ip6tables"

    def _exists(self, binary: str, args: list[str]) -> bool:
        try:
            self.runner([binary, "-C", *args], None)
        except DriverError:
            return False
        return True

    def ensure_ready(self, desired: Iterable[str]) -> None:
        for binary in ("iptables", "ip6tables"):
            if not self._exists(binary, [CHAIN, "-j", "RETURN"]):
                with contextlib.suppress(DriverError):  # chain may already exist
                    self.runner([binary, "-N", CHAIN], None)
                self.runner([binary, "-F", CHAIN], None)  # our chain only
                self.runner([binary, "-A", CHAIN, "-j", "RETURN"], None)
            for parent in ("FORWARD", "INPUT"):
                if not self._exists(binary, [parent, "-j", CHAIN]):
                    self.runner([binary, "-I", parent, "1", "-j", CHAIN], None)
        for ip in desired:
            self.quarantine(ip)

    def _rules(self, addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> list[list[str]]:
        return [
            [CHAIN, "-s", addr.compressed, "-j", "DROP"],
            [CHAIN, "-d", addr.compressed, "-j", "DROP"],
        ]

    def quarantine(self, ip: str) -> None:
        addr = parse_ip(ip)
        binary = self._bin(addr)
        for rule in self._rules(addr):
            if not self._exists(binary, rule):
                self.runner([binary, "-I", *rule[:1], "1", *rule[1:]], None)

    def release(self, ip: str) -> None:
        addr = parse_ip(ip)
        binary = self._bin(addr)
        for rule in self._rules(addr):
            while self._exists(binary, rule):
                self.runner([binary, "-D", *rule], None)

    def active(self) -> set[str]:
        found: set[str] = set()
        for binary in ("iptables", "ip6tables"):
            try:
                out = self.runner([binary, "-S", CHAIN], None)
            except DriverError:
                continue
            for line in out.splitlines():
                parts = line.split()
                if "-s" in parts and parts[-1] == "DROP":
                    found.add(parse_ip(parts[parts.index("-s") + 1].split("/")[0]).compressed)
        return found


def build_driver(kind: str, dry_run: bool, runner: Runner = run_command) -> ResponseDriver:
    if dry_run or kind == "dryrun":
        return DryRunDriver()
    if kind == "nftables":
        if shutil.which("nft") is None and runner is run_command:
            raise DriverError("nft binary not found")
        return NftablesDriver(runner)
    if kind == "iptables":
        if shutil.which("iptables") is None and runner is run_command:
            raise DriverError("iptables binary not found")
        return IptablesDriver(runner)
    raise DriverError(f"unknown response driver {kind!r}")
