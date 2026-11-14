#include "util/hash.hpp"

#include <doctest/doctest.h>

#include <string>

#include "util/hex.hpp"

using namespace sister_sign;
using namespace sister_sign::util;

namespace {
std::string sha_hex(std::string_view s) {
  ByteView v(reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
  auto d = sha256(v);
  REQUIRE(d.has_value());
  return hex_lower(*d);
}
}  // namespace

TEST_CASE("sha256 known vectors") {
  CHECK(sha_hex("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  CHECK(sha_hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  CHECK(sha_hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") ==
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

TEST_CASE("sha256 streaming equals one-shot") {
  Bytes data(1u << 20);
  for (std::size_t i = 0; i < data.size(); ++i) data[i] = static_cast<std::uint8_t>(i * 31);
  auto whole = sha256(data);
  REQUIRE(whole.has_value());

  Sha256 h;
  ByteView v(data);
  for (std::size_t off = 0; off < v.size(); off += 4099) {
    auto chunk = v.subspan(off, std::min<std::size_t>(4099, v.size() - off));
    REQUIRE(h.update(chunk).has_value());
  }
  auto streamed = h.finish();
  REQUIRE(streamed.has_value());
  CHECK(*streamed == *whole);
}

TEST_CASE("sha256 context cannot be reused after finish") {
  Sha256 h;
  REQUIRE(h.finish().has_value());
  CHECK_FALSE(h.finish().has_value());
  CHECK_FALSE(h.update(Bytes{1}).has_value());
}

TEST_CASE("sha256 of the empty update equals sha256 of nothing") {
  Sha256 h;
  REQUIRE(h.update(ByteView{}).has_value());
  auto d = h.finish();
  REQUIRE(d.has_value());
  CHECK(hex_lower(*d) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}
