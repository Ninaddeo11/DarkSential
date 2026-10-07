// Portable status-node logic: command verification, LED state machine,
// provisioning-console parser, reconnect backoff, telemetry payload.
// No Arduino dependencies: unit-tested on the host (pio test -e native).
#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>

namespace dsn {

// ---- Commands ------------------------------------------------------------------
// Wire format and signature contract: backend/app/mqtt/commands.py.
struct Command {
  std::string id;
  int64_t ts = 0;
  std::string cmd;
  std::string node_id;
  std::string level;
  int64_t ttl = 0;
  std::string sig;
};

enum class Verdict { kOk, kBadJson, kBadField, kBadCmd, kBadSig, kStale, kReplay };
const char* verdict_name(Verdict v);

// Parses the JSON payload (bounded; unknown keys ignored). False on malformed input.
bool parse_command(const char* json, size_t len, Command& out);

// "id|ts|cmd|node_id|level|ttl"; empty if any field has a character outside
// [A-Za-z0-9._:-] (so no field can smuggle the separator).
std::string signing_string(const Command& c);

// Remembers the last N command ids to reject replays.
class ReplayCache {
 public:
  bool seen(const std::string& id) const;
  void remember(const std::string& id);

 private:
  static constexpr size_t kSize = 32;
  std::string ids_[kSize];
  size_t next_ = 0;
};

// Full check: fields, command name, signature (constant-time), staleness
// (|now - ts| <= ttl, ttl capped at 300 s), replay. Remembers the id on success.
Verdict verify_command(const Command& c, const uint8_t* key, size_t key_len, int64_t now,
                       ReplayCache& replay);

// ---- LED state -----------------------------------------------------------------
enum class LedState { kBoot, kProvision, kOffline, kNormal, kAlert, kQuarantined };
const char* led_state_name(LedState s);
LedState state_for_command(const std::string& cmd, LedState current);

struct Rgb {
  uint8_t r, g, b;
};
// Colour for a state at time t_ms (blinking/breathing are pure functions of time).
Rgb led_color(LedState s, uint32_t t_ms);

// ---- Provisioning console --------------------------------------------------------
// Lines: "set <key> <value>", "ca_begin" ... PEM ... "ca_end", "show", "commit", "wipe".
class Provisioner {
 public:
  enum class Result { kOk, kCommit, kWipe, kShow, kError, kNeedMore };
  Result feed(const std::string& line, std::string& message);
  const std::map<std::string, std::string>& values() const { return values_; }
  bool complete(std::string& missing) const;
  static bool allowed_key(const std::string& key);

 private:
  std::map<std::string, std::string> values_;
  bool in_ca_ = false;
  std::string ca_;
};

// ---- Reconnect backoff -----------------------------------------------------------
// Exponential with full jitter: uniform in [0, min(cap, base * 2^attempt)].
// `rand01` in [0, 1) is injected so the logic is deterministic in tests.
uint32_t backoff_ms(uint32_t attempt, uint32_t base_ms, uint32_t cap_ms, double rand01);

// ---- Telemetry -------------------------------------------------------------------
struct TelemetryData {
  std::string mac, ip, fw;
  uint32_t uptime_s = 0;
  int32_t rssi = 0;
  uint32_t heap = 0;
  LedState state = LedState::kBoot;
  uint32_t seq = 0;
};
std::string telemetry_json(const TelemetryData& t);

}  // namespace dsn
