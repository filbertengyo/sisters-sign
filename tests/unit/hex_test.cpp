#include "util/hex.hpp"

#include <doctest/doctest.h>

#include <string>

using namespace sister_sign;
using namespace sister_sign::util;

TEST_CASE("hex_lower") {
  CHECK(hex_lower(Bytes{}) == "");
  const Bytes b{0x00, 0x0f, 0xa5, 0xff};
  CHECK(hex_lower(b) == "000fa5ff");
}

TEST_CASE("hex_decode valid") {
  auto r = hex_decode("000fa5ff");
  REQUIRE(r.has_value());
  CHECK(*r == Bytes{0x00, 0x0f, 0xa5, 0xff});
  auto empty = hex_decode("");
  REQUIRE(empty.has_value());
  CHECK(empty->empty());
}

TEST_CASE("hex_decode rejects non-canonical input") {
  for (const char* bad : {"A", "ab1", "0F", "ABCD", "zz", "0g", " 00", "00 ", "0x00", "-1"}) {
    auto r = hex_decode(bad);
    CHECK_MESSAGE(!r.has_value(), bad);
    if (!r.has_value()) CHECK(r.error().status == Status::FormatError);
  }
  const std::string with_nul(
      "00\0"
      "0",
      4);
  CHECK_FALSE(hex_decode(with_nul).has_value());
}

TEST_CASE("hex roundtrip for lengths 0..64") {
  for (std::size_t n = 0; n <= 64; ++n) {
    Bytes b(n);
    for (std::size_t i = 0; i < n; ++i) b[i] = static_cast<std::uint8_t>(i * 37 + n);
    auto back = hex_decode(hex_lower(b));
    REQUIRE(back.has_value());
    CHECK(*back == b);
  }
}
