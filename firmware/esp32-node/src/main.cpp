// Darknet Sentinel Nexus - ESP32 status/telemetry node.
//
// Defensive lab device: it shows the backend's verdict on an RGB LED and reports
// its own health. It never scans, sniffs, or sends anything except its own telemetry
// and command acks. All security-relevant logic (HMAC verification, staleness,
// replay, provisioning parsing) lives in lib/dsn_core and is unit-tested on the host.
//
// Credentials are entered over USB serial at provisioning time and stored in NVS;
// nothing secret is compiled in. See README.md.

#include <Arduino.h>
#include <PubSubClient.h>
#include <Preferences.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <esp_random.h>
#include <time.h>

#include <string>

#include "dsn_core.h"

#ifdef DSN_ENABLE_BLE
#include <BLE2902.h>
#include <BLEDevice.h>
#include <BLEServer.h>
#endif

#ifndef DSN_PIN_R
#define DSN_PIN_R 25
#endif
#ifndef DSN_PIN_G
#define DSN_PIN_G 26
#endif
#ifndef DSN_PIN_B
#define DSN_PIN_B 27
#endif
#ifndef DSN_PIN_PROVISION
#define DSN_PIN_PROVISION 0
#endif

namespace {

constexpr const char* kFirmwareVersion = "0.6.0";
constexpr const char* kNvsNamespace = "dsn";
constexpr uint32_t kTelemetryEveryMs = 10000;
constexpr uint32_t kBackoffBaseMs = 1000;
constexpr uint32_t kBackoffCapMs = 60000;
constexpr int64_t kMinValidEpoch = 1700000000;  // clock not synced before this
constexpr uint32_t kLedFreq = 5000;
constexpr uint8_t kLedBits = 8;

struct Config {
  String wifi_ssid, wifi_pass, mqtt_host, mqtt_user, mqtt_pass, ca_pem, cmd_key;
  uint16_t mqtt_port = 8883;
};

Config cfg;
Preferences prefs;
WiFiClientSecure tls;
PubSubClient mqtt(tls);
dsn::ReplayCache replay;
dsn::LedState state = dsn::LedState::kBoot;
dsn::LedState last_verdict = dsn::LedState::kNormal;  // restored after reconnect
uint32_t mqtt_attempt = 0, next_mqtt_try = 0, last_telemetry = 0, seq = 0;
String topic_cmd, topic_ack, topic_telemetry;

#ifdef DSN_ENABLE_BLE
BLECharacteristic* ble_state = nullptr;
#endif

double rand01() { return double(esp_random()) / 4294967296.0; }

// ---- LED -----------------------------------------------------------------------
void led_begin() {
#if ESP_ARDUINO_VERSION_MAJOR >= 3
  ledcAttach(DSN_PIN_R, kLedFreq, kLedBits);
  ledcAttach(DSN_PIN_G, kLedFreq, kLedBits);
  ledcAttach(DSN_PIN_B, kLedFreq, kLedBits);
#else
  const int pins[3] = {DSN_PIN_R, DSN_PIN_G, DSN_PIN_B};
  for (int ch = 0; ch < 3; ++ch) {
    ledcSetup(ch, kLedFreq, kLedBits);
    ledcAttachPin(pins[ch], ch);
  }
#endif
}

void led_write(uint8_t r, uint8_t g, uint8_t b) {
#ifdef DSN_LED_COMMON_ANODE
  r = 255 - r; g = 255 - g; b = 255 - b;
#endif
#if ESP_ARDUINO_VERSION_MAJOR >= 3
  ledcWrite(DSN_PIN_R, r);
  ledcWrite(DSN_PIN_G, g);
  ledcWrite(DSN_PIN_B, b);
#else
  ledcWrite(0, r);
  ledcWrite(1, g);
  ledcWrite(2, b);
#endif
}

void led_tick() {
  const dsn::Rgb c = dsn::led_color(state, millis());
  led_write(c.r, c.g, c.b);
}

void set_state(dsn::LedState s) {
  if (s == state) return;
  state = s;
  Serial.printf("[dsn] state %s\n", dsn::led_state_name(s));
#ifdef DSN_ENABLE_BLE
  if (ble_state != nullptr) {
    const char* name = dsn::led_state_name(s);
    ble_state->setValue(reinterpret_cast<uint8_t*>(const_cast<char*>(name)), strlen(name));
    ble_state->notify();
  }
#endif
}

// ---- NVS config ---------------------------------------------------------------------
bool load_config() {
  prefs.begin(kNvsNamespace, true);
  cfg.wifi_ssid = prefs.getString("wifi_ssid", "");
  cfg.wifi_pass = prefs.getString("wifi_pass", "");
  cfg.mqtt_host = prefs.getString("mqtt_host", "");
  cfg.mqtt_port = prefs.getUShort("mqtt_port", 8883);
  cfg.mqtt_user = prefs.getString("mqtt_user", "");
  cfg.mqtt_pass = prefs.getString("mqtt_pass", "");
  cfg.ca_pem = prefs.getString("ca_pem", "");
  cfg.cmd_key = prefs.getString("cmd_key", "");
  prefs.end();
  return cfg.wifi_ssid.length() && cfg.mqtt_host.length() && cfg.mqtt_user.length() &&
         cfg.mqtt_pass.length() && cfg.ca_pem.length();
}

void save_config(const dsn::Provisioner& p) {
  prefs.begin(kNvsNamespace, false);
  prefs.clear();
  for (const auto& kv : p.values()) {
    if (kv.first == "mqtt_port") {
      prefs.putUShort("mqtt_port", uint16_t(atoi(kv.second.c_str())));
    } else {
      prefs.putString(kv.first.c_str(), kv.second.c_str());
    }
  }
  prefs.end();
}

// Interactive serial console. Secrets are never echoed back.
void provisioning_console() {
  set_state(dsn::LedState::kProvision);
  Serial.println("[dsn] provisioning mode: set <key> <value> | ca_begin..ca_end | show | commit | wipe");
  dsn::Provisioner p;
  std::string line, msg;
  for (;;) {
    led_tick();
    while (Serial.available()) {
      const char ch = char(Serial.read());
      if (ch != '\n') {
        if (line.size() < 512) line.push_back(ch);
        continue;
      }
      const auto r = p.feed(line, msg);
      line.clear();
      switch (r) {
        case dsn::Provisioner::Result::kOk:
        case dsn::Provisioner::Result::kError:
          Serial.printf("[dsn] %s\n", msg.c_str());
          break;
        case dsn::Provisioner::Result::kShow:
          for (const auto& kv : p.values()) {
            const bool secret = kv.first == "wifi_pass" || kv.first == "mqtt_pass" ||
                                kv.first == "cmd_key";
            Serial.printf("  %s = %s\n", kv.first.c_str(),
                          secret ? "<set>" : (kv.first == "ca_pem" ? "<pem>" : kv.second.c_str()));
          }
          break;
        case dsn::Provisioner::Result::kWipe:
          prefs.begin(kNvsNamespace, false);
          prefs.clear();
          prefs.end();
          Serial.println("[dsn] NVS wiped");
          break;
        case dsn::Provisioner::Result::kCommit: {
          std::string missing;
          if (!p.complete(missing)) {
            Serial.printf("[dsn] missing %s\n", missing.c_str());
            break;
          }
          save_config(p);
          Serial.println("[dsn] saved; rebooting");
          delay(200);
          ESP.restart();
        }
        case dsn::Provisioner::Result::kNeedMore:
          break;
      }
    }
    delay(5);
  }
}

// ---- Network ------------------------------------------------------------------------
bool clock_synced() { return time(nullptr) >= kMinValidEpoch; }

void publish_ack(const std::string& id, dsn::Verdict v) {
  String payload = "{\"id\":\"";
  // Only ids that passed the charset check are echoed verbatim.
  payload += (v == dsn::Verdict::kBadJson || v == dsn::Verdict::kBadField) ? "" : id.c_str();
  payload += "\",\"status\":\"";
  payload += dsn::verdict_name(v);
  payload += "\"}";
  mqtt.publish(topic_ack.c_str(), payload.c_str());
}

void on_message(char* topic, byte* payload, unsigned int len) {
  if (topic_cmd != topic) return;
  dsn::Command c;
  if (!dsn::parse_command(reinterpret_cast<const char*>(payload), len, c)) {
    publish_ack("", dsn::Verdict::kBadJson);
    return;
  }
  if (!clock_synced()) {  // cannot judge staleness yet: refuse rather than guess
    publish_ack(c.id, dsn::Verdict::kStale);
    return;
  }
  const dsn::Verdict v =
      dsn::verify_command(c, reinterpret_cast<const uint8_t*>(cfg.cmd_key.c_str()),
                          cfg.cmd_key.length(), int64_t(time(nullptr)), replay);
  Serial.printf("[dsn] command %s -> %s\n", c.cmd.c_str(), dsn::verdict_name(v));
  if (v == dsn::Verdict::kOk) {
    last_verdict = dsn::state_for_command(c.cmd, last_verdict);
    set_state(last_verdict);
  }
  publish_ack(c.id, v);
}

void wifi_begin() {
  WiFi.mode(WIFI_STA);
  WiFi.setAutoReconnect(true);
  WiFi.begin(cfg.wifi_ssid.c_str(), cfg.wifi_pass.c_str());
  configTime(0, 0, "pool.ntp.org", "time.google.com");
}

void mqtt_loop() {
  if (WiFi.status() != WL_CONNECTED) {
    set_state(dsn::LedState::kOffline);
    return;
  }
  if (mqtt.connected()) {
    mqtt.loop();
    return;
  }
  set_state(dsn::LedState::kOffline);
  if (millis() < next_mqtt_try) return;
  const String client_id = cfg.mqtt_user + "-" + String(uint32_t(ESP.getEfuseMac()), HEX);
  Serial.printf("[dsn] mqtt connect %s:%u attempt %u\n", cfg.mqtt_host.c_str(), cfg.mqtt_port,
                mqtt_attempt);
  if (mqtt.connect(client_id.c_str(), cfg.mqtt_user.c_str(), cfg.mqtt_pass.c_str())) {
    mqtt_attempt = 0;
    if (cfg.cmd_key.length() >= 32) mqtt.subscribe(topic_cmd.c_str(), 1);
    set_state(last_verdict);
    last_telemetry = 0;  // report immediately
    return;
  }
  const uint32_t wait = dsn::backoff_ms(mqtt_attempt, kBackoffBaseMs, kBackoffCapMs, rand01());
  if (mqtt_attempt < 16) ++mqtt_attempt;
  next_mqtt_try = millis() + wait;
  Serial.printf("[dsn] mqtt failed rc=%d, retry in %u ms\n", mqtt.state(), wait);
}

void telemetry_tick() {
  if (!mqtt.connected()) return;
  if (last_telemetry != 0 && millis() - last_telemetry < kTelemetryEveryMs) return;
  last_telemetry = millis() | 1;
  dsn::TelemetryData t;
  t.mac = WiFi.macAddress().c_str();
  t.ip = WiFi.localIP().toString().c_str();
  t.fw = kFirmwareVersion;
  t.uptime_s = millis() / 1000;
  t.rssi = WiFi.RSSI();
  t.heap = ESP.getFreeHeap();
  t.state = state;
  t.seq = ++seq;
  const std::string body = dsn::telemetry_json(t);
  mqtt.publish(topic_telemetry.c_str(), body.c_str());
}

#ifdef DSN_ENABLE_BLE
// Read/notify-only GATT service exposing the LED state. No writable characteristics:
// BLE cannot be used to change the node's state or configuration.
void ble_begin() {
  BLEDevice::init(("dsn-" + cfg.mqtt_user).c_str());
  BLEServer* server = BLEDevice::createServer();
  BLEService* svc = server->createService("6e0f0001-5d6b-4c1e-9a4a-6473736e0001");
  ble_state = svc->createCharacteristic("6e0f0002-5d6b-4c1e-9a4a-6473736e0001",
                                        BLECharacteristic::PROPERTY_READ |
                                            BLECharacteristic::PROPERTY_NOTIFY);
  ble_state->addDescriptor(new BLE2902());
  const char* name = dsn::led_state_name(state);
  ble_state->setValue(reinterpret_cast<uint8_t*>(const_cast<char*>(name)), strlen(name));
  svc->start();
  BLEDevice::getAdvertising()->addServiceUUID(svc->getUUID());
  BLEDevice::startAdvertising();
}
#endif

}  // namespace

void setup() {
  Serial.begin(115200);
  pinMode(DSN_PIN_PROVISION, INPUT_PULLUP);
  led_begin();
  led_tick();
  delay(300);
  Serial.printf("\n[dsn] Darknet Sentinel Nexus node fw %s\n", kFirmwareVersion);
  const bool forced = digitalRead(DSN_PIN_PROVISION) == LOW;
  if (forced || !load_config()) provisioning_console();  // never returns

  topic_cmd = "dsn/cmd/" + cfg.mqtt_user;
  topic_ack = "dsn/ack/" + cfg.mqtt_user;
  topic_telemetry = "dsn/telemetry/" + cfg.mqtt_user;
  if (cfg.cmd_key.length() > 0 && cfg.cmd_key.length() < 32) {
    Serial.println("[dsn] cmd_key shorter than 32 bytes: commands disabled");
  }

  tls.setCACert(cfg.ca_pem.c_str());  // server cert must chain to the lab CA
  mqtt.setServer(cfg.mqtt_host.c_str(), cfg.mqtt_port);
  mqtt.setBufferSize(1024);
  mqtt.setKeepAlive(30);
  mqtt.setCallback(on_message);
#ifdef DSN_ENABLE_BLE
  ble_begin();
#endif
  wifi_begin();
  set_state(dsn::LedState::kOffline);
}

void loop() {
  mqtt_loop();
  telemetry_tick();
  led_tick();
  delay(10);
}
