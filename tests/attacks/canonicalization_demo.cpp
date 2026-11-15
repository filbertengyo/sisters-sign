#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <glaze/glaze.hpp>
#include <manifest/manifest.hpp>

struct RawArtifact {
  std::string name;
  std::uint64_t size = 0;
  std::string sha256;
};

struct RawManifest {
  std::string schema;
  std::string package;
  std::string version;
  std::string algorithm;
  std::string keyid;
  RawArtifact artifact;
};

TEST_CASE("canonicalization demo") {
    std::string manifest_string = R"({"schema":"minisign-manifest/v1","package":"demo-package","version":"1.0","algorithm":"ed25519","keyid":"abcdffff","artifact":{"name":"demo-artifact","size":8192,"sha256":"decafbad","sha256":"fee1dead"}})";

    SUBCASE("naive keep-first parser") {
        RawManifest manifest;
        auto error = glz::read<glz::opts{.partial_read=true}>(manifest, manifest_string);
        if (error) FAIL("read failed");
        CHECK(manifest.artifact.sha256 == "decafbad");
    }
    SUBCASE("naive keep-last parser") {
        RawManifest manifest;
        auto error = glz::read_json(manifest, manifest_string);
        if (error) FAIL("read failed");
        CHECK(manifest.artifact.sha256 == "fee1dead");
    }
    SUBCASE("strict parser") {
        auto res = sister_sign::manifest::parse(manifest_string);
        CHECK(res.error().status == sister_sign::Status::FormatError);
    }
}
