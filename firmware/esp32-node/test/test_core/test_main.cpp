// Host-side tests for the portable status-node logic (pio test -e native).
// The command vector is shared with backend/tests/test_iot_backend.py, so the
// Python signer and the C++ verifier are pinned to the same bytes.
#include <unity.h>

#include <cstring>
#include <string>

#include "dsn_core.h"
#include "sha256.h"

using namespace dsn;

namespace {

const char* kKey = "status-node-command-key-0123456789abcdef";
const char* kVectorSig = "80bf20325c28621746d8e521ea080dae4a88304630db3a9ba85f661bf60681e3";
const int64_t kVectorTs = 1790000000;

Command vector_command() {
  Command c;
  c.id = "4a0f7c4e-1111-4222-8333-444455556666";
  c.ts = kVectorTs;
  c.cmd = "QUARANTINE";
  c.node_id = "dev-8b32829a42842662";
  c.level = "critical";
  c.ttl = 60;
  c.sig = kVectorSig;
  return c;
}

Verdict verify(const Command& c, int64_t now, ReplayCache& r) {
  return verify_command(c, reinterpret_cast<const uint8_t*>(kKey), std::strlen(kKey), now, r);
}

std::string sha_hex(const std::string& s) {
  Sha256 h;
  h.update(reinterpret_cast<const uint8_t*>(s.data()), s.size());
  uint8_t out[kSha256Size];
  h.finish(out);
  return to_hex(out, kSha256Size);
}

std::string hmac_hex(const std::string& key, const std::string& msg) {
  uint8_t out[kSha256Size];
  hmac_sha256(reinterpret_cast<const uint8_t*>(key.data()), key.size(),
              reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), out);
  return to_hex(out, kSha256Size);
}

}  // namespace

void setUp() {}
void tearDown() {}

// ---- SHA-256 / HMAC known answers ------------------------------------------------
void test_sha256_known_answers() {
  TEST_ASSERT_EQUAL_STRING(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", sha_hex("").c_str());
  TEST_ASSERT_EQUAL_STRING(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", sha_hex("abc").c_str());
  // 56-byte message: padding spills into a second block.
  TEST_ASSERT_EQUAL_STRING(
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
      sha_hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq").c_str());
  std::string million(1000000, 'a');
  TEST_ASSERT_EQUAL_STRING(
      "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
      sha_hex(million).c_str());
}

void test_hmac_rfc4231() {
  // RFC 4231 test case 2.
  TEST_ASSERT_EQUAL_STRING(
      "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
      hmac_hex("Jefe", "what do ya want for nothing?").c_str());
  // RFC 4231 test case 6: key longer than the block size is hashed first.
  TEST_ASSERT_EQUAL_STRING(
      "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
      hmac_hex(std::string(131, '\xaa'),
               "Test Using Larger Than Block-Size Key - Hash Key First")
          .c_str());
}

void test_hex_equal_ct() {
  TEST_ASSERT_TRUE(hex_equal_ct("abcd", "abcd"));
  TEST_ASSERT_FALSE(hex_equal_ct("abcd", "abce"));
  TEST_ASSERT_FALSE(hex_equal_ct("abcd", "abc"));
}

// ---- Command contract (shared with the backend) ------------------------------------
void test_signing_string_matches_backend() {
  TEST_ASSERT_EQUAL_STRING(
      "4a0f7c4e-1111-4222-8333-444455556666|1790000000|QUARANTINE|dev-8b32829a42842662|"
      "critical|60",
      signing_string(vector_command()).c_str());
}

void test_vector_signature_matches_backend() {
  const std::string msg = signing_string(vector_command());
  TEST_ASSERT_EQUAL_STRING(kVectorSig, hmac_hex(kKey, msg).c_str());
}

void test_signing_string_rejects_separator_smuggling() {
  Command c = vector_command();
  c.node_id = "dev|x";
  TEST_ASSERT_EQUAL_STRING("", signing_string(c).c_str());
  c = vector_command();
  c.level = "crit ical";
  TEST_ASSERT_EQUAL_STRING("", signing_string(c).c_str());
}

void test_parse_command_roundtrip() {
  const char* json =
      "{\"id\":\"4a0f7c4e-1111-4222-8333-444455556666\",\"ts\":1790000000,"
      "\"cmd\":\"QUARANTINE\",\"node_id\":\"dev-8b32829a42842662\",\"level\":\"critical\","
      "\"ttl\":60,\"sig\":\"80bf20325c28621746d8e521ea080dae4a88304630db3a9ba85f661bf60681e3\","
      "\"extra\":[1,2,3]}";
  Command c;
  TEST_ASSERT_TRUE(parse_command(json, std::strlen(json), c));
  TEST_ASSERT_EQUAL_STRING("QUARANTINE", c.cmd.c_str());
  TEST_ASSERT_EQUAL_INT64(kVectorTs, c.ts);
  ReplayCache r;
  TEST_ASSERT_EQUAL(static_cast<int>(Verdict::kOk), static_cast<int>(verify(c, kVectorTs + 5, r)));
}

void test_parse_command_defaults_and_rejects() {
  Command c;
  const char* minimal = "{\"id\":\"a\",\"ts\":1,\"cmd\":\"RECOVER\",\"ttl\":30,\"sig\":\"x\"}";
  TEST_ASSERT_TRUE(parse_command(minimal, std::strlen(minimal), c));
  TEST_ASSERT_EQUAL_STRING("", c.node_id.c_str());
  TEST_ASSERT_EQUAL_STRING("", c.level.c_str());

  const char* bad[] = {
      "not json",
      "[1,2]",
      "{\"id\":\"a\",\"ts\":\"1\",\"cmd\":\"RECOVER\",\"ttl\":30,\"sig\":\"x\"}",  // ts string
      "{\"id\":\"a\",\"cmd\":\"RECOVER\",\"ttl\":30,\"sig\":\"x\"}",               // ts missing
      "{\"id\":5,\"ts\":1,\"cmd\":\"RECOVER\",\"ttl\":30,\"sig\":\"x\"}",          // id number
  };
  for (const char* b : bad) TEST_ASSERT_FALSE(parse_command(b, std::strlen(b), c));
  TEST_ASSERT_FALSE(parse_command(nullptr, 0, c));
  std::string huge(2000, ' ');
  TEST_ASSERT_FALSE(parse_command(huge.c_str(), huge.size(), c));
}

void test_verify_rejects_tampering() {
  ReplayCache r;
  Command c = vector_command();
  c.cmd = "RECOVER";  // valid command name, but not what was signed
  TEST_ASSERT_EQUAL(static_cast<int>(Verdict::kBadSig), static_cast<int>(verify(c, kVectorTs, r)));
  c = vector_command();
  c.ttl = 61;
  TEST_ASSERT_EQUAL(static_cast<int>(Verdict::kBadSig), static_cast<int>(verify(c, kVectorTs, r)));
  c = vector_command();
  c.sig[0] = c.sig[0] == '0' ? '1' : '0';
  TEST_ASSERT_EQUAL(static_cast<int>(Verdict::kBadSig), static_cast<int>(verify(c, kVectorTs, r)));
  c = vector_command();
  c.sig = "short";
  TEST_ASSERT_EQUAL(static_cast<int>(Verdict::kBadField),
                    static_cast<int>(verify(c, kVectorTs, r)));
  c = vector_command();
  c.cmd = "REBOOT";
  TEST_ASSERT_EQUAL(static_cast<int>(Verdict::kBadCmd), static_cast<int>(verify(c, kVectorTs, r)));
  c = vector_command();
  c.id = "";
  TEST_ASSERT_EQUAL(static_cast<int>(Verdict::kBadField),
                    static_cast<int>(verify(c, kVectorTs, r)));
}

void test_verify_wrong_key() {
  ReplayCache r;
  const char* other = "a-different-key-that-is-at-least-32-bytes";
  TEST_ASSERT_EQUAL(static_cast<int>(Verdict::kBadSig),
                    static_cast<int>(verify_command(vector_command(),
                                                    reinterpret_cast<const uint8_t*>(other),
                                                    std::strlen(other), kVectorTs, r)));
}

void test_verify_staleness_window() {
  ReplayCache r1, r2, r3, r4;
  // ttl = 60: accepted at exactly +/-60 s, stale beyond (clock skew both ways).
  TEST_ASSERT_EQUAL(static_cast<int>(Verdict::kOk),
                    static_cast<int>(verify(vector_command(), kVectorTs + 60, r1)));
  TEST_ASSERT_EQUAL(static_cast<int>(Verdict::kOk),
                    static_cast<int>(verify(vector_command(), kVectorTs - 60, r2)));
  TEST_ASSERT_EQUAL(static_cast<int>(Verdict::kStale),
                    static_cast<int>(verify(vector_command(), kVectorTs + 61, r3)));
  TEST_ASSERT_EQUAL(static_cast<int>(Verdict::kStale),
                    static_cast<int>(verify(vector_command(), kVectorTs - 61, r4)));
}

void test_verify_rejects_replay_but_not_after_eviction() {
  ReplayCache r;
  TEST_ASSERT_EQUAL(static_cast<int>(Verdict::kOk),
                    static_cast<int>(verify(vector_command(), kVectorTs, r)));
  TEST_ASSERT_EQUAL(static_cast<int>(Verdict::kReplay),
                    static_cast<int>(verify(vector_command(), kVectorTs, r)));
  // A stale or bad-sig message must not poison the cache.
  ReplayCache fresh;
  Command bad = vector_command();
  bad.sig[0] = bad.sig[0] == '0' ? '1' : '0';
  verify(bad, kVectorTs, fresh);
  TEST_ASSERT_FALSE(fresh.seen(bad.id));
  // Ring buffer: after 32 other ids the original falls out (staleness still bounds replays).
  for (int i = 0; i < 32; ++i) r.remember("other-" + std::to_string(i));
  TEST_ASSERT_FALSE(r.seen(vector_command().id));
}

// ---- LED state machine -------------------------------------------------------------
void test_state_transitions() {
  TEST_ASSERT_EQUAL(static_cast<int>(LedState::kQuarantined),
                    static_cast<int>(state_for_command("QUARANTINE", LedState::kNormal)));
  TEST_ASSERT_EQUAL(static_cast<int>(LedState::kAlert),
                    static_cast<int>(state_for_command("ALERT", LedState::kNormal)));
  TEST_ASSERT_EQUAL(static_cast<int>(LedState::kQuarantined),
                    static_cast<int>(state_for_command("ALERT", LedState::kQuarantined)));
  TEST_ASSERT_EQUAL(static_cast<int>(LedState::kNormal),
                    static_cast<int>(state_for_command("RECOVER", LedState::kQuarantined)));
  TEST_ASSERT_EQUAL(static_cast<int>(LedState::kNormal),
                    static_cast<int>(state_for_command("NORMAL", LedState::kAlert)));
  TEST_ASSERT_EQUAL(static_cast<int>(LedState::kAlert),
                    static_cast<int>(state_for_command("BOGUS", LedState::kAlert)));
  TEST_ASSERT_EQUAL_STRING("QUARANTINED", led_state_name(LedState::kQuarantined));
}

void test_led_colors() {
  Rgb n = led_color(LedState::kNormal, 0);
  TEST_ASSERT_EQUAL_UINT8(0, n.r);
  TEST_ASSERT_TRUE(n.g > 0);
  Rgb a_on = led_color(LedState::kAlert, 0), a_off = led_color(LedState::kAlert, 600);
  TEST_ASSERT_TRUE(a_on.r > 0 && a_on.g > 0);
  TEST_ASSERT_EQUAL_UINT8(0, a_off.r);
  // Quarantine "breathes" red: never off, never green/blue, brightest mid-cycle.
  Rgb q0 = led_color(LedState::kQuarantined, 0), q1 = led_color(LedState::kQuarantined, 1000);
  TEST_ASSERT_TRUE(q0.r > 0);
  TEST_ASSERT_TRUE(q1.r > q0.r);
  TEST_ASSERT_EQUAL_UINT8(0, q1.g);
  TEST_ASSERT_EQUAL_UINT8(0, q1.b);
}

// ---- Provisioning console ------------------------------------------------------------
void test_provisioner_happy_path() {
  Provisioner p;
  std::string msg, missing;
  const char* lines[] = {"set wifi_ssid lab-iot", "set wifi_pass s3cret pass",
                         "set mqtt_host 192.168.50.2", "set mqtt_port 8883",
                         "set mqtt_user status-node", "set mqtt_pass pw\r"};
  for (const char* l : lines) {
    TEST_ASSERT_EQUAL(static_cast<int>(Provisioner::Result::kOk), static_cast<int>(p.feed(l, msg)));
  }
  TEST_ASSERT_FALSE(p.complete(missing));
  TEST_ASSERT_EQUAL_STRING("ca_pem", missing.c_str());
  TEST_ASSERT_EQUAL(static_cast<int>(Provisioner::Result::kNeedMore),
                    static_cast<int>(p.feed("ca_begin", msg)));
  p.feed("-----BEGIN CERTIFICATE-----", msg);
  p.feed("MIIBszCCAVmgAwIBAgIU", msg);
  p.feed("-----END CERTIFICATE-----", msg);
  TEST_ASSERT_EQUAL(static_cast<int>(Provisioner::Result::kOk),
                    static_cast<int>(p.feed("ca_end", msg)));
  TEST_ASSERT_TRUE(p.complete(missing));
  TEST_ASSERT_EQUAL_STRING("s3cret pass", p.values().at("wifi_pass").c_str());
  TEST_ASSERT_EQUAL_STRING("pw", p.values().at("mqtt_pass").c_str());
  TEST_ASSERT_EQUAL(static_cast<int>(Provisioner::Result::kCommit),
                    static_cast<int>(p.feed("commit", msg)));
}

void test_provisioner_rejects_bad_input() {
  Provisioner p;
  std::string msg;
  const char* bad[] = {"set evil_key x", "set mqtt_port 0", "set mqtt_port 70000",
                       "set mqtt_port 88a", "set wifi_ssid", "rm -rf /"};
  for (const char* b : bad) {
    TEST_ASSERT_EQUAL(static_cast<int>(Provisioner::Result::kError),
                      static_cast<int>(p.feed(b, msg)));
  }
  TEST_ASSERT_EQUAL(static_cast<int>(Provisioner::Result::kError),
                    static_cast<int>(p.feed("set wifi_ssid " + std::string(200, 'x'), msg)));
  p.feed("ca_begin", msg);
  p.feed("not a pem", msg);
  TEST_ASSERT_EQUAL(static_cast<int>(Provisioner::Result::kError),
                    static_cast<int>(p.feed("ca_end", msg)));
  p.feed("ca_begin", msg);
  Provisioner::Result last = Provisioner::Result::kNeedMore;
  for (int i = 0; i < 200 && last == Provisioner::Result::kNeedMore; ++i) {
    last = p.feed(std::string(64, 'A'), msg);
  }
  TEST_ASSERT_EQUAL(static_cast<int>(Provisioner::Result::kError), static_cast<int>(last));
  TEST_ASSERT_EQUAL(0, static_cast<int>(p.values().size()));
  TEST_ASSERT_EQUAL(static_cast<int>(Provisioner::Result::kNeedMore),
                    static_cast<int>(p.feed("# comment", msg)));
}

// ---- Backoff ---------------------------------------------------------------------------
void test_backoff_bounds() {
  TEST_ASSERT_EQUAL_UINT32(0, backoff_ms(0, 500, 60000, 0.0));
  TEST_ASSERT_EQUAL_UINT32(250, backoff_ms(0, 500, 60000, 0.5));
  TEST_ASSERT_EQUAL_UINT32(1000, backoff_ms(2, 500, 60000, 0.5));
  // Capped, and large attempt counts do not overflow.
  TEST_ASSERT_EQUAL_UINT32(30000, backoff_ms(30, 500, 60000, 0.5));
  TEST_ASSERT_EQUAL_UINT32(30000, backoff_ms(4000000000u, 500, 60000, 0.5));
  TEST_ASSERT_TRUE(backoff_ms(30, 500, 60000, 1.0) < 60000);
  TEST_ASSERT_EQUAL_UINT32(0, backoff_ms(3, 500, 60000, -1.0));
}

// ---- Telemetry ---------------------------------------------------------------------------
void test_telemetry_json_shape() {
  TelemetryData t;
  t.mac = "24:0a:c4:00:11:22";
  t.ip = "192.168.50.31";
  t.fw = "0.6.0";
  t.uptime_s = 42;
  t.rssi = -61;
  t.heap = 201234;
  t.state = LedState::kNormal;
  t.seq = 7;
  TEST_ASSERT_EQUAL_STRING(
      "{\"v\":1,\"mac\":\"24:0a:c4:00:11:22\",\"ip\":\"192.168.50.31\",\"fw\":\"0.6.0\","
      "\"uptime_s\":42,\"rssi\":-61,\"heap\":201234,\"state\":\"NORMAL\",\"seq\":7}",
      telemetry_json(t).c_str());
}

int main() {
  UNITY_BEGIN();
  RUN_TEST(test_sha256_known_answers);
  RUN_TEST(test_hmac_rfc4231);
  RUN_TEST(test_hex_equal_ct);
  RUN_TEST(test_signing_string_matches_backend);
  RUN_TEST(test_vector_signature_matches_backend);
  RUN_TEST(test_signing_string_rejects_separator_smuggling);
  RUN_TEST(test_parse_command_roundtrip);
  RUN_TEST(test_parse_command_defaults_and_rejects);
  RUN_TEST(test_verify_rejects_tampering);
  RUN_TEST(test_verify_wrong_key);
  RUN_TEST(test_verify_staleness_window);
  RUN_TEST(test_verify_rejects_replay_but_not_after_eviction);
  RUN_TEST(test_state_transitions);
  RUN_TEST(test_led_colors);
  RUN_TEST(test_provisioner_happy_path);
  RUN_TEST(test_provisioner_rejects_bad_input);
  RUN_TEST(test_backoff_bounds);
  RUN_TEST(test_telemetry_json_shape);
  return UNITY_END();
}
