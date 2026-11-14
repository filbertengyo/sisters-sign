#include "util/base64.hpp"

#include <doctest/doctest.h>

#include <string>

using namespace sister_sign;
using namespace sister_sign::util;

namespace {
Bytes bytes_of(std::string_view s) { return Bytes(s.begin(), s.end()); }
}  // namespace

TEST_CASE("base64 RFC 4648 test vectors") {
  struct V {
    const char* plain;
    const char* b64;
  };
  const V vectors[] = {{"", ""},
                       {"f", "Zg=="},
                       {"fo", "Zm8="},
                       {"foo", "Zm9v"},
                       {"foob", "Zm9vYg=="},
                       {"fooba", "Zm9vYmE="},
                       {"foobar", "Zm9vYmFy"}};
  for (const auto& v : vectors) {
    CHECK(base64_encode(bytes_of(v.plain)) == v.b64);
    auto d = base64_decode(v.b64);
    REQUIRE(d.has_value());
    CHECK(*d == bytes_of(v.plain));
  }
}

TEST_CASE("base64 roundtrip for lengths 0..64") {
  for (std::size_t n = 0; n <= 64; ++n) {
    Bytes b(n);
    for (std::size_t i = 0; i < n; ++i) b[i] = static_cast<std::uint8_t>(i * 53 + n * 7);
    auto back = base64_decode(base64_encode(b));
    REQUIRE(back.has_value());
    CHECK(*back == b);
  }
}

TEST_CASE("base64 decode rejects non-canonical input") {
  const std::string with_nul("Zm9v\0", 5);
  const char* bad[] = {
      " Zm9v",       "Zm9v ", "Zm9v\n",   "Zm9v\r\n", "Zm\n9v",    "Zm 9v",  // whitespace
      "Zg=",         "Zg",    "Zm9vYg",   "Zm9vYg=",  "Zm9vYg===",           // padding
      "Zg=a",        "Z=g=",  "=Zg=",     "====",     "Zm9v=Zm9",            // padding posisi
      "Zm-v",        "Zm_v",  "Zm9v-_==", "Zm.v",     "Zm*v",                // alfabet
      "QR==",        "Zh==",  "Zm9=",                                        // trailing bits
      "Zm9\xC3\xA9",                                                         // non-ASCII
  };
  for (const char* s : bad) {
    auto r = base64_decode(s);
    CHECK_MESSAGE(!r.has_value(), s);
    if (!r.has_value()) CHECK(r.error().status == Status::FormatError);
  }
  CHECK_FALSE(base64_decode(with_nul).has_value());
}

TEST_CASE("base64 trailing bits: QQ== is canonical, QR== is not") {
  auto ok = base64_decode("QQ==");
  REQUIRE(ok.has_value());
  CHECK(*ok == bytes_of("A"));
  CHECK_FALSE(base64_decode("QR==").has_value());
}
