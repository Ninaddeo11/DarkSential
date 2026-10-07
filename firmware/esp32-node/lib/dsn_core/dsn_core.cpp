#include "dsn_core.h"

#include <ArduinoJson.h>

#include <cmath>
#include <cstdlib>

#include "sha256.h"

namespace dsn {
namespace {

constexpr size_t kMaxField = 96;
constexpr int64_t kMaxTtl = 300;

bool safe_field(const std::string& s) {
  if (s.size() > kMaxField) return false;
  for (char ch : s) {
    bool ok = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') ||
              ch == '.' || ch == '_' || ch == ':' || ch == '-';
    if (!ok) return false;
  }
  return true;
}

}  // namespace

const char* verdict_name(Verdict v) {
  switch (v) {
    case Verdict::kOk: return "ok";
    case Verdict::kBadJson: return "bad_json";
    case Verdict::kBadField: return "bad_field";
    case Verdict::kBadCmd: return "bad_cmd";
    case Verdict::kBadSig: return "bad_sig";
    case Verdict::kStale: return "stale";
    case Verdict::kReplay: return "replay";
  }
  return "unknown";
}

bool parse_command(const char* json, size_t len, Command& out) {
  if (json == nullptr || len == 0 || len > 1024) return false;
  JsonDocument doc;
  if (deserializeJson(doc, json, len) != DeserializationError::Ok) return false;
  if (!doc.is<JsonObject>()) return false;
  auto str = [&](const char* key, std::string& dst) {
    JsonVariant v = doc[key];
    if (v.isNull()) { dst.clear(); return true; }
    if (!v.is<const char*>()) return false;
    dst = v.as<const char*>();
    return dst.size() <= kMaxField * 2;
  };
  if (!doc["ts"].is<int64_t>() || !doc["ttl"].is<int64_t>()) return false;
  out.ts = doc["ts"].as<int64_t>();
  out.ttl = doc["ttl"].as<int64_t>();
  return str("id", out.id) && str("cmd", out.cmd) && str("node_id", out.node_id) &&
         str("level", out.level) && str("sig", out.sig);
}

std::string signing_string(const Command& c) {
  const std::string ts = std::to_string(c.ts), ttl = std::to_string(c.ttl);
  for (const std::string* f : {&c.id, &ts, &c.cmd, &c.node_id, &c.level, &ttl}) {
    if (!safe_field(*f)) return "";
  }
  return c.id + "|" + ts + "|" + c.cmd + "|" + c.node_id + "|" + c.level + "|" + ttl;
}

bool ReplayCache::seen(const std::string& id) const {
  for (const auto& s : ids_) {
    if (!s.empty() && s == id) return true;
  }
  return false;
}

void ReplayCache::remember(const std::string& id) {
  ids_[next_] = id;
  next_ = (next_ + 1) % kSize;
}

Verdict verify_command(const Command& c, const uint8_t* key, size_t key_len, int64_t now,
                       ReplayCache& replay) {
  if (c.id.empty() || c.sig.size() != kSha256Size * 2) return Verdict::kBadField;
  const std::string msg = signing_string(c);
  if (msg.empty()) return Verdict::kBadField;
  if (c.cmd != "QUARANTINE" && c.cmd != "ALERT" && c.cmd != "RECOVER" && c.cmd != "NORMAL") {
    return Verdict::kBadCmd;
  }
  uint8_t mac[kSha256Size];
  hmac_sha256(key, key_len, reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), mac);
  if (!hex_equal_ct(to_hex(mac, kSha256Size), c.sig)) return Verdict::kBadSig;
  const int64_t ttl = c.ttl < 1 ? 1 : (c.ttl > kMaxTtl ? kMaxTtl : c.ttl);
  const int64_t skew = now > c.ts ? now - c.ts : c.ts - now;
  if (skew > ttl) return Verdict::kStale;
  if (replay.seen(c.id)) return Verdict::kReplay;
  replay.remember(c.id);
  return Verdict::kOk;
}

const char* led_state_name(LedState s) {
  switch (s) {
    case LedState::kBoot: return "BOOT";
    case LedState::kProvision: return "PROVISION";
    case LedState::kOffline: return "OFFLINE";
    case LedState::kNormal: return "NORMAL";
    case LedState::kAlert: return "ALERT";
    case LedState::kQuarantined: return "QUARANTINED";
  }
  return "BOOT";
}

LedState state_for_command(const std::string& cmd, LedState current) {
  if (cmd == "QUARANTINE") return LedState::kQuarantined;
  // An ALERT never downgrades an active quarantine indication.
  if (cmd == "ALERT") return current == LedState::kQuarantined ? current : LedState::kAlert;
  if (cmd == "RECOVER" || cmd == "NORMAL") return LedState::kNormal;
  return current;
}

Rgb led_color(LedState s, uint32_t t_ms) {
  const bool blink = (t_ms / 500) % 2 == 0;  // 1 Hz
  switch (s) {
    case LedState::kBoot: return {0, 0, 80};                       // dim blue
    case LedState::kProvision: return {blink ? uint8_t(120) : uint8_t(0), 0, 120};  // purple
    case LedState::kOffline: return {0, 0, blink ? uint8_t(160) : uint8_t(0)};      // blue blink
    case LedState::kNormal: return {0, 120, 0};                    // green
    case LedState::kAlert:                                          // amber blink
      return blink ? Rgb{255, 120, 0} : Rgb{0, 0, 0};
    case LedState::kQuarantined: {                                  // red "breathing"
      const double phase = (t_ms % 2000) / 2000.0;
      const double level = 0.25 + 0.75 * (0.5 - 0.5 * std::cos(phase * 2 * 3.14159265358979));
      return {uint8_t(255 * level), 0, 0};
    }
  }
  return {0, 0, 0};
}

bool Provisioner::allowed_key(const std::string& key) {
  return key == "wifi_ssid" || key == "wifi_pass" || key == "mqtt_host" || key == "mqtt_port" ||
         key == "mqtt_user" || key == "mqtt_pass" || key == "cmd_key";
}

Provisioner::Result Provisioner::feed(const std::string& raw, std::string& message) {
  std::string line = raw;
  while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
  if (in_ca_) {
    if (line == "ca_end") {
      in_ca_ = false;
      if (ca_.find("-----BEGIN CERTIFICATE-----") == std::string::npos || ca_.size() > 4096) {
        ca_.clear();
        message = "invalid CA PEM";
        return Result::kError;
      }
      values_["ca_pem"] = ca_;
      ca_.clear();
      message = "CA stored";
      return Result::kOk;
    }
    ca_ += line + "\n";
    if (ca_.size() > 4096) {
      in_ca_ = false;
      ca_.clear();
      message = "CA too large";
      return Result::kError;
    }
    return Result::kNeedMore;
  }
  if (line.empty() || line[0] == '#') return Result::kNeedMore;
  if (line == "ca_begin") {
    in_ca_ = true;
    ca_.clear();
    return Result::kNeedMore;
  }
  if (line == "commit") return Result::kCommit;
  if (line == "wipe") return Result::kWipe;
  if (line == "show") return Result::kShow;
  if (line.rfind("set ", 0) == 0) {
    const size_t sp = line.find(' ', 4);
    if (sp == std::string::npos) {
      message = "usage: set <key> <value>";
      return Result::kError;
    }
    const std::string key = line.substr(4, sp - 4), value = line.substr(sp + 1);
    if (!allowed_key(key)) {
      message = "unknown key";
      return Result::kError;
    }
    if (value.empty() || value.size() > 128) {
      message = "bad value length";
      return Result::kError;
    }
    if (key == "mqtt_port") {
      char* end = nullptr;
      const long port = std::strtol(value.c_str(), &end, 10);
      if (*end != '\0' || port < 1 || port > 65535) {
        message = "bad port";
        return Result::kError;
      }
    }
    values_[key] = value;
    message = key + " set";
    return Result::kOk;
  }
  message = "unknown command";
  return Result::kError;
}

bool Provisioner::complete(std::string& missing) const {
  for (const char* k : {"wifi_ssid", "wifi_pass", "mqtt_host", "mqtt_port", "mqtt_user",
                        "mqtt_pass", "ca_pem"}) {
    if (values_.find(k) == values_.end()) {
      missing = k;
      return false;
    }
  }
  return true;
}

uint32_t backoff_ms(uint32_t attempt, uint32_t base_ms, uint32_t cap_ms, double rand01) {
  double ceiling = double(base_ms);
  for (uint32_t i = 0; i < attempt && ceiling < cap_ms; ++i) ceiling *= 2;
  if (ceiling > cap_ms) ceiling = cap_ms;
  if (rand01 < 0) rand01 = 0;
  if (rand01 >= 1) rand01 = 0.999999;
  return uint32_t(ceiling * rand01);
}

std::string telemetry_json(const TelemetryData& t) {
  JsonDocument doc;
  doc["v"] = 1;
  doc["mac"] = t.mac;
  doc["ip"] = t.ip;
  doc["fw"] = t.fw;
  doc["uptime_s"] = t.uptime_s;
  doc["rssi"] = t.rssi;
  doc["heap"] = t.heap;
  doc["state"] = led_state_name(t.state);
  doc["seq"] = t.seq;
  std::string out;
  serializeJson(doc, out);
  return out;
}

}  // namespace dsn
