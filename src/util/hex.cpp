#include "util/hex.hpp"

namespace sister_sign::util {

std::string hex_lower(ByteView bytes) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (std::uint8_t b : bytes) {
    out.push_back(kDigits[b >> 4]);
    out.push_back(kDigits[b & 0x0F]);
  }
  return out;
}

namespace {
int nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}
}  // namespace

Outcome<Bytes> hex_decode(std::string_view hex) {
  if (hex.size() % 2 != 0) return make_error(Status::FormatError, "hex: panjang ganjil");
  Bytes out;
  out.reserve(hex.size() / 2);
  for (std::size_t i = 0; i < hex.size(); i += 2) {
    const int hi = nibble(hex[i]);
    const int lo = nibble(hex[i + 1]);
    if (hi < 0 || lo < 0) return make_error(Status::FormatError, "hex: karakter tidak valid");
    out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
  }
  return out;
}

}  // namespace sister_sign::util
