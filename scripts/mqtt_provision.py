#!/usr/bin/env python3
"""Provision the lab MQTT broker: TLS PKI, per-client credentials, device files.

    cd backend && uv run python ../scripts/mqtt_provision.py \\
        --host mosquitto --ip 10.77.2.10 --device cam-front --device thermo-hall

Writes (all git-ignored, contains secrets):
  infra/mosquitto/certs/ca.crt, ca.key, server.crt, server.key
  infra/mosquitto/passwd                 Mosquitto password file ($7$ PBKDF2-SHA512)
  infra/mosquitto/credentials.json       usernames/passwords + status-node command key
  infra/lab/secrets/<user>.json         one file per virtual lab client (its own
                                         credentials only; the status node also
                                         gets the command key)

Idempotent: re-running keeps the CA, the server key and existing passwords and
adds new devices. ``--rotate`` issues a new CA and new server certificate (all
lab clients pick up the new CA on restart).

Users and their ACL roles (infra/mosquitto/config/acl):
  dsn-backend   publishes commands, reads telemetry/acks
  status-node   reads its command topic, writes acks + its telemetry
  <device>      writes dsn/telemetry/<device> and home/<device>/# only
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parents[1]
MOSQ = ROOT / "infra" / "mosquitto"
# PBKDF2 iterations: mosquitto_passwd defaults to 101, which is weak. 20000 keeps a
# broker-side check around a few ms, so a connection flood can't cheaply burn CPU.
PBKDF2_ITERATIONS = 20000
FIXED_USERS = ("dsn-backend", "status-node")


def mosquitto_hash(password: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    """Mosquitto 2.x ``$7$`` format: PBKDF2-HMAC-SHA512, 12-byte salt, 64-byte hash."""
    salt = os.urandom(12)
    digest = hashlib.pbkdf2_hmac("sha512", password.encode(), salt, iterations, dklen=64)
    return f"$7${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def _key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _write_key(path: Path, key: ec.EllipticCurvePrivateKey) -> None:
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    path.chmod(0o600)


def make_ca(certs: Path) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    key = _key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "DSN Lab MQTT CA")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                                     key_encipherment=False, data_encipherment=False,
                                     key_agreement=False, key_cert_sign=True, crl_sign=True,
                                     encipher_only=False, decipher_only=False), critical=True)
        .sign(key, hashes.SHA256())
    )
    _write_key(certs / "ca.key", key)
    (certs / "ca.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert, key


def make_server(certs: Path, ca: x509.Certificate, ca_key: ec.EllipticCurvePrivateKey,
                hosts: list[str], ips: list[str]) -> None:
    key_path = certs / "server.key"
    if key_path.exists():
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        assert isinstance(key, ec.EllipticCurvePrivateKey)
    else:
        key = _key()
        _write_key(key_path, key)
    sans: list[x509.GeneralName] = [x509.DNSName(h) for h in hosts]
    sans += [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hosts[0])]))
        .issuer_name(ca.subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=825))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    (certs / "server.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def provision(out: Path, hosts: list[str], ips: list[str], devices: list[str],
              rotate: bool = False, device_dir: Path | None = None) -> dict[str, object]:
    certs = out / "certs"
    certs.mkdir(parents=True, exist_ok=True)
    creds_path = out / "credentials.json"
    creds: dict[str, object] = json.loads(creds_path.read_text()) if creds_path.exists() else {}
    users: dict[str, str] = dict(creds.get("users", {}))  # type: ignore[call-overload]
    if rotate or not (certs / "ca.crt").exists():
        for stale in ("server.key", "server.crt"):
            (certs / stale).unlink(missing_ok=True)
        ca, ca_key = make_ca(certs)
    else:
        ca = x509.load_pem_x509_certificate((certs / "ca.crt").read_bytes())
        loaded = serialization.load_pem_private_key((certs / "ca.key").read_bytes(), None)
        assert isinstance(loaded, ec.EllipticCurvePrivateKey)
        ca_key = loaded
    make_server(certs, ca, ca_key, hosts, ips)
    for user in (*FIXED_USERS, *devices):
        if not all(c.isalnum() or c in "-_" for c in user) or len(user) > 64:
            raise SystemExit(f"invalid username {user!r} (use letters, digits, - and _)")
        users.setdefault(user, secrets.token_urlsafe(24))
    command_key = str(creds.get("command_key") or secrets.token_urlsafe(32))
    creds = {"users": users, "command_key": command_key, "hosts": hosts, "ips": ips}
    creds_path.write_text(json.dumps(creds, indent=2), encoding="utf-8")
    creds_path.chmod(0o600)
    passwd = out / "passwd"
    passwd.write_text("".join(f"{u}:{mosquitto_hash(p)}\n" for u, p in sorted(users.items())),
                      encoding="utf-8")
    passwd.chmod(0o600)
    if device_dir is not None:
        device_dir.mkdir(parents=True, exist_ok=True)
        for user in ("status-node", *devices):
            entry: dict[str, str] = {"username": user, "password": users[user]}
            if user == "status-node":
                entry["command_key"] = command_key
            path = device_dir / f"{user}.json"
            path.write_text(json.dumps(entry, indent=2), encoding="utf-8")
            path.chmod(0o600)
    return creds


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--host", action="append", default=[], help="broker DNS name (SAN)")
    parser.add_argument("--ip", action="append", default=[], help="broker IP (SAN)")
    parser.add_argument("--device", action="append", default=[], help="device username")
    parser.add_argument("--out", type=Path, default=MOSQ)
    parser.add_argument("--rotate", action="store_true", help="issue a new CA + server cert")
    parser.add_argument("--no-device-files", action="store_true",
                        help="don't write per-client files for the virtual lab")
    args = parser.parse_args()
    hosts = args.host or ["mosquitto", "localhost"]
    device_dir = None if args.no_device_files else ROOT / "infra" / "lab" / "secrets"
    creds = provision(args.out, hosts, args.ip or ["127.0.0.1"], args.device, args.rotate,
                      device_dir)
    users = creds["users"]
    assert isinstance(users, dict)
    print(f"provisioned {len(users)} MQTT users in {args.out}")
    print("Add to .env for the backend:")
    print("  DSN_MQTT_USERNAME=dsn-backend")
    print("  DSN_MQTT_PASSWORD=<see infra/mosquitto/credentials.json>")
    print("  DSN_MQTT_COMMAND_KEY=<command_key from the same file>")
    if device_dir is not None:
        print(f"Virtual lab client files: {device_dir}")


if __name__ == "__main__":
    main()
