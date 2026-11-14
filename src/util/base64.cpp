#include "util/base64.hpp"

#include <array>

namespace sister_sign::util {

namespace {

constexpr char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

constexpr std::array<std::int8_t, 256> make_table() {
  std::array<std::int8_t, 256> t{};
  for (auto& v : t) v = -1;
  for (int i = 0; i < 64; ++i) {
    t[static_cast<unsigned char>(kAlphabet[i])] = static_cast<std::int8_t>(i);
  }
  return t;
}
constexpr auto kTable = make_table();

Error bad(const char* why) { return Error{Status::FormatError, std::string("base64: ") + why}; }

}  // namespace

std::string base64_encode(ByteView in) {
  std::string out;
  out.reserve((in.size() + 2) / 3 * 4);
  std::size_t i = 0;
  for (; i + 3 <= in.size(); i += 3) {
    const std::uint32_t v = (in[i] << 16) | (in[i + 1] << 8) | in[i + 2];
    out.push_back(kAlphabet[(v >> 18) & 63]);
    out.push_back(kAlphabet[(v >> 12) & 63]);
    out.push_back(kAlphabet[(v >> 6) & 63]);
    out.push_back(kAlphabet[v & 63]);
  }
  const std::size_t rest = in.size() - i;
  if (rest == 1) {
    const std::uint32_t v = static_cast<std::uint32_t>(in[i]) << 16;
    out.push_back(kAlphabet[(v >> 18) & 63]);
    out.push_back(kAlphabet[(v >> 12) & 63]);
    out += "==";
  } else if (rest == 2) {
    const std::uint32_t v = (in[i] << 16) | (in[i + 1] << 8);
    out.push_back(kAlphabet[(v >> 18) & 63]);
    out.push_back(kAlphabet[(v >> 12) & 63]);
    out.push_back(kAlphabet[(v >> 6) & 63]);
    out.push_back('=');
  }
  return out;
}

Outcome<Bytes> base64_decode(std::string_view text) {
  if (text.size() % 4 != 0) return std::unexpected(bad("panjang bukan kelipatan 4"));

  Bytes out;
  out.reserve(text.size() / 4 * 3);
  for (std::size_t i = 0; i < text.size(); i += 4) {
    const bool last = i + 4 == text.size();
    std::uint32_t v[4];
    int pad = 0;
    for (int j = 0; j < 4; ++j) {
      const auto c = static_cast<unsigned char>(text[i + j]);
      if (c == '=') {
        // Padding hanya boleh di posisi 3-4 blok terakhir.
        if (!last || j < 2) return std::unexpected(bad("padding di posisi salah"));
        ++pad;
        v[j] = 0;
      } else {
        if (pad != 0) return std::unexpected(bad("karakter setelah padding"));
        const int d = kTable[c];
        if (d < 0) return std::unexpected(bad("karakter di luar alfabet"));
        v[j] = static_cast<std::uint32_t>(d);
      }
    }
    const std::uint32_t n = (v[0] << 18) | (v[1] << 12) | (v[2] << 6) | v[3];
    out.push_back(static_cast<std::uint8_t>(n >> 16));
    if (pad < 2) out.push_back(static_cast<std::uint8_t>(n >> 8));
    if (pad < 1) out.push_back(static_cast<std::uint8_t>(n));
    // Bit sisa yang tidak dipakai harus nol (kalau tidak, ada dua teks untuk byte yang sama).
    if (pad == 2 && (n & 0xFFFF) != 0) return std::unexpected(bad("trailing bits tidak nol"));
    if (pad == 1 && (n & 0xFF) != 0) return std::unexpected(bad("trailing bits tidak nol"));
  }

  // Sabuk pengaman: hasil encode ulang harus identik dengan input.
  if (base64_encode(out) != text) return std::unexpected(bad("bukan bentuk kanonik"));
  return out;
}

}  // namespace sister_sign::util
