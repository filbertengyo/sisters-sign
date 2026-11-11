#include "util/result.hpp"

#include <doctest/doctest.h>

#include <set>
#include <string>

#include "crypto/crypto.hpp"

using namespace sister_sign;

namespace {
constexpr Status kAll[] = {Status::Ok,
                           Status::InputError,
                           Status::FormatError,
                           Status::UnsupportedAlgorithm,
                           Status::KeyNotTrusted,
                           Status::InvalidSignature,
                           Status::MetadataMismatch,
                           Status::ArtifactMismatch};
}

TEST_CASE("status names") {
  CHECK(to_string(Status::Ok) == "OK");
  CHECK(to_string(Status::InputError) == "INPUT_ERROR");
  CHECK(to_string(Status::FormatError) == "FORMAT_ERROR");
  CHECK(to_string(Status::UnsupportedAlgorithm) == "UNSUPPORTED_ALGORITHM");
  CHECK(to_string(Status::KeyNotTrusted) == "KEY_NOT_TRUSTED");
  CHECK(to_string(Status::InvalidSignature) == "INVALID_SIGNATURE");
  CHECK(to_string(Status::MetadataMismatch) == "METADATA_MISMATCH");
  CHECK(to_string(Status::ArtifactMismatch) == "ARTIFACT_MISMATCH");
}

TEST_CASE("status names are unique") {
  std::set<std::string> names;
  for (Status s : kAll) names.emplace(to_string(s));
  CHECK(names.size() == std::size(kAll));
}

TEST_CASE("exit codes") {
  CHECK(exit_code(Status::Ok) == 0);
  CHECK(exit_code(Status::InputError) == 2);
  for (Status s : {Status::FormatError, Status::UnsupportedAlgorithm, Status::KeyNotTrusted,
                   Status::InvalidSignature, Status::MetadataMismatch, Status::ArtifactMismatch}) {
    CHECK(exit_code(s) == 1);
  }
}

TEST_CASE("ok_result and fail") {
  Result ok = ok_result();
  CHECK(ok.valid);
  CHECK(ok.status == Status::Ok);

  Result bad = fail(Status::KeyNotTrusted, "no such key");
  CHECK_FALSE(bad.valid);
  CHECK(bad.status == Status::KeyNotTrusted);
  CHECK(bad.message == "no such key");
}

TEST_CASE("Outcome carries value or Error") {
  Outcome<int> good = 42;
  REQUIRE(good.has_value());
  CHECK(*good == 42);

  Outcome<int> bad = make_error(Status::FormatError, "bad json");
  REQUIRE_FALSE(bad.has_value());
  CHECK(bad.error().status == Status::FormatError);
  CHECK(bad.error().message == "bad json");
}

TEST_CASE("signature sizes per profile") {
  using crypto::Algorithm;
  CHECK(crypto::signature_size(Algorithm::RsaPss) == 384);
  CHECK(crypto::signature_size(Algorithm::EcdsaP256) == 64);
  CHECK(crypto::signature_size(Algorithm::Ed25519) == 64);
}
