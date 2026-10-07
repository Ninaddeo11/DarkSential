// Portable SHA-256 and HMAC-SHA256 (FIPS 180-4 / RFC 2104).
// One implementation for the device and the native unit tests, so the signature
// check that runs on the ESP32 is exactly the code the tests verify.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace dsn {

constexpr size_t kSha256Size = 32;

class Sha256 {
 public:
  Sha256();
  void update(const uint8_t* data, size_t len);
  void finish(uint8_t out[kSha256Size]);

 private:
  void block(const uint8_t* chunk);
  uint32_t h_[8];
  uint8_t buf_[64];
  size_t buf_len_ = 0;
  uint64_t total_ = 0;
};

void hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* msg, size_t msg_len,
                 uint8_t out[kSha256Size]);

std::string to_hex(const uint8_t* data, size_t len);

// Constant-time comparison of two hex strings of equal length.
bool hex_equal_ct(const std::string& a, const std::string& b);

}  // namespace dsn
