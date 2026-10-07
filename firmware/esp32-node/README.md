# ESP32 status / telemetry node

A small lab device for Darknet Sentinel Nexus. It does two jobs:

- It **shows the backend's verdict** on an RGB LED. Commands are signed with HMAC.
- It **reports its own health** (telemetry) over MQTT/TLS.

It is a passive, defensive device. It does not scan, sniff, deauthenticate or attack anything. It only publishes its own telemetry and its command acks.

## Layout

| Path | What |
|---|---|
| `lib/dsn_core/` | Portable C++ with no Arduino code: SHA-256/HMAC, command parse and verify (signature, staleness, replay), LED state machine, provisioning parser, backoff, telemetry JSON |
| `src/main.cpp` | Arduino glue: NVS (Preferences), serial provisioning, WiFi, MQTT over TLS (PubSubClient), NTP, LED PWM, optional BLE |
| `test/test_core/` | Unity tests for `dsn_core`, run on the host |

The command signature contract is shared with `backend/app/mqtt/commands.py`. The C++ tests and `backend/tests/test_iot_backend.py` both check the same test vector, so the signer and the verifier cannot drift apart unnoticed.

## Hardware and wiring

Parts:

- ESP32 DevKit (ESP32-WROOM-32, `esp32dev`)
- One RGB LED, common cathode
- Three 220 Ω resistors

| LED leg | Resistor | ESP32 pin |
|---|---|---|
| Red | 220 Ω | GPIO 25 |
| Green | 220 Ω | GPIO 26 |
| Blue | 220 Ω | GPIO 27 |
| Common cathode (longest leg) | none | GND |

```
GPIO25 ──[220Ω]──┐
GPIO26 ──[220Ω]──┤ RGB LED (common cathode) ── GND
GPIO27 ──[220Ω]──┘
GPIO0 (BOOT button) ── held LOW at reset → provisioning console
```

For a **common-anode** LED:

1. Connect the common leg to 3V3 instead of GND.
2. Add `-DDSN_LED_COMMON_ANODE=1` to `build_flags`.

To use different pins, change the `DSN_PIN_*` flags in `platformio.ini`.

### LED states

| State | Colour | Meaning |
|---|---|---|
| BOOT | dim blue | starting up |
| PROVISION | purple blink | serial provisioning console is active |
| OFFLINE | blue blink | WiFi or MQTT is down; reconnecting with backoff |
| NORMAL | solid green | connected; the last verdict was normal or recovered |
| ALERT | amber blink | backend sent `ALERT` |
| QUARANTINED | red "breathing" | backend sent `QUARANTINE`; a later `ALERT` does not downgrade it |

## Build, test, flash

You need PlatformIO Core 6.2.0 (`pip install platformio==6.2.0`). Run these from this directory:

```sh
pio test -e native                    # unit tests on the host (no board needed)
pio run -e esp32dev                   # build the firmware
pio run -e esp32dev -t upload         # flash over USB
pio device monitor                    # serial console at 115200 baud
```

`esp32dev_ble` adds a **read/notify-only** BLE GATT service that exposes the LED state:

- Service `6e0f0001-5d6b-4c1e-9a4a-6473736e0001`
- Characteristic `6e0f0002-…`

It has no writable characteristic, so BLE cannot change the node's state or its configuration. The BLE build uses the `huge_app.csv` partition table (no OTA slot), because WiFi, TLS and Bluedroid together do not fit in the default app partition.

Without a local toolchain, `python scripts/tasks.py firmware-test` (from the repo root) runs the tests and both builds in Docker.

## Provisioning

No credentials are compiled in. They live in the ESP32's NVS and are entered over USB serial.

1. **Generate credentials** on the backend host (also run by `python scripts/tasks.py setup`):

   ```sh
   python scripts/mqtt_provision.py --host <broker-lan-ip> --ip <broker-lan-ip>
   ```

   This writes `firmware/esp32-node/provisioning/<user>.txt` for `status-node` and for each `--device`. The directory is gitignored.
2. **Edit the file**: replace `<your-lab-ssid>` and `<your-lab-wifi-password>`.
3. **Flash** the firmware. A node with no configuration starts in provisioning mode on its own. To re-provision an already configured node, hold **BOOT** while you press **EN/reset**.
4. **Send the file** over serial. For example, open `pio device monitor` and paste the file's contents, or run:

   ```sh
   python -c "import serial,sys,time; s=serial.Serial(sys.argv[1],115200); [ (s.write((l.rstrip()+'\n').encode()), time.sleep(0.05)) for l in open(sys.argv[2]) ]" COM5 provisioning/status-node.txt
   ```

   (On Linux, use a port such as `/dev/ttyUSB0` instead of `COM5`.)

   After `commit` the node saves its configuration and reboots.

Console commands:

| Command | Effect |
|---|---|
| `set <key> <value>` | Set one value. Keys: `wifi_ssid`, `wifi_pass`, `mqtt_host`, `mqtt_port`, `mqtt_user`, `mqtt_pass`, `cmd_key` |
| `ca_begin` … PEM lines … `ca_end` | Store the lab CA certificate |
| `show` | List the values. Secrets print as `<set>` |
| `commit` | Save and reboot. Refused if a required value is missing |
| `wipe` | Erase NVS |

`cmd_key` is optional:

- Without it, the node is **telemetry-only**: it never subscribes to commands.
- Keys shorter than 32 bytes are rejected at boot.

## MQTT contract

| Topic | Direction | Payload |
|---|---|---|
| `dsn/telemetry/<user>` | node → broker, every 10 s | `{"v":1,"mac","ip","fw","uptime_s","rssi","heap","state","seq"}` |
| `dsn/cmd/<user>` | backend → node | `{"id","ts","cmd","node_id","level","ttl","sig"}` |
| `dsn/ack/<user>` | node → backend | `{"id","status"}` with status `ok`, `bad_json`, `bad_field`, `bad_cmd`, `bad_sig`, `stale` or `replay` |

The broker ACL (`infra/mosquitto/config/acl`) restricts each user to exactly these topics.

### How the node checks a command

1. **Fields.** Every field must match `[A-Za-z0-9._:-]`, so no field can contain the `|` separator.
2. **Command.** The command must be one of `QUARANTINE`, `ALERT`, `RECOVER` or `NORMAL`.
3. **Signature.** It recomputes `HMAC-SHA256(cmd_key, "id|ts|cmd|node_id|level|ttl")` and compares it with `sig` in constant time.
4. **Staleness.** It accepts the command only if `|now − ts| ≤ ttl`. `ttl` is clamped to 1–300 s.
5. **Replay.** It rejects a command ID it has already accepted. It remembers the last 32 IDs. Only accepted commands are remembered, so a forged message cannot poison the cache.

Until NTP has set the clock, every command is acked `stale` rather than accepted on a guess.

## Known limitations

- **Untested on real hardware.** The firmware compiles for `esp32dev`, with and without BLE, and its portable logic passes 18 host tests. It has **not** been run on a physical board in this repo's CI, so the WiFi, TLS, NVS and LED paths are unverified on silicon.
- **Replay protection does not survive a reboot.** The replay cache lives in RAM. After a reboot, the only protection against a replayed command is the staleness window, which is at most 300 s.
- **No client certificate.** TLS authenticates the broker using the lab CA, and the node authenticates with a username and password. Mutual TLS is not implemented.
- **NTP servers are fixed.** They are hard-coded to `pool.ntp.org` and `time.google.com`. A lab with no internet access needs a local NTP server, and the code must be changed to point at it.
- **NVS is not encrypted.** Secrets are stored in plaintext in NVS unless you enable ESP32 flash encryption and NVS encryption, which this project does not configure.
