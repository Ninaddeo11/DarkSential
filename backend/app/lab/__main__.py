"""``python -m app.lab``: run a virtual lab client.

device --profile camera|vulncam|thermostat|plug|sensor [--seed N]
status-node [--seed N]
attack flood [--per-minute 500] [--minutes 2]
attack wildcard [--seconds 60]
attack restricted [--count 10]
attack bad-auth [--attempts 20]
attack c2 [--target 162.243.103.246:8080] [--count 5] [--interval 3]
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading

from app.lab.devices import PROFILES


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.lab")
    sub = parser.add_subparsers(dest="role", required=True)
    dev = sub.add_parser("device")
    dev.add_argument("--profile", choices=sorted(PROFILES), required=True)
    dev.add_argument("--seed", type=int, default=7)
    node = sub.add_parser("status-node")
    node.add_argument("--seed", type=int, default=7)
    atk = sub.add_parser("attack")
    atk.add_argument("kind", choices=["flood", "wildcard", "restricted", "bad-auth", "c2"])
    atk.add_argument("--per-minute", type=int, default=500)
    atk.add_argument("--minutes", type=float, default=2.0)
    atk.add_argument("--seconds", type=float, default=60.0)
    atk.add_argument("--count", type=int, default=10)
    atk.add_argument("--attempts", type=int, default=20)
    atk.add_argument("--target", default="162.243.103.246:8080")  # Feodo fixture IP
    atk.add_argument("--interval", type=float, default=3.0)
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())

    from app.lab import attacks, client

    if args.role == "attack" and args.kind == "c2":
        print(f"c2 attempts: {attacks.c2_beacon(args.target, args.count, args.interval, stop)}")
        return 0
    cfg = client.LabConfig.from_env()
    if args.role == "device":
        client.run_device(cfg, args.profile, args.seed, stop)
    elif args.role == "status-node":
        client.run_status_node(cfg, args.seed, stop)
    elif args.kind == "flood":
        print(f"connects: {attacks.connect_flood(cfg, args.per_minute, args.minutes, stop)}")
    elif args.kind == "wildcard":
        print(f"subscribed: {attacks.wildcard_subscribe(cfg, args.seconds, stop)}")
    elif args.kind == "restricted":
        print(f"published: {attacks.restricted_publish(cfg, args.count, stop)}")
    else:
        print(f"refused logins: {attacks.bad_auth(cfg, args.attempts, stop)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
