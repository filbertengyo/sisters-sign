#include <doctest/doctest.h>
#include <openssl/evp.h>

#include <glaze/glaze.hpp>
#include <string>

#include "util/version.hpp"

namespace {
struct Simple {
  int a{};
};
}  // namespace

TEST_CASE("version string is not empty") { CHECK_FALSE(sister_sign::util::version().empty()); }

TEST_CASE("glaze parses simple JSON") {
  Simple s;
  CHECK_FALSE(glz::read_json(s, std::string(R"({"a":1})")));
  CHECK(s.a == 1);
}

TEST_CASE("glaze rejects malformed JSON") {
  Simple s;
  CHECK(glz::read_json(s, std::string(R"({"a":)")));
}

TEST_CASE("libcrypto is linked") { CHECK(EVP_sha256() != nullptr); }
