#include "manifest/manifest.hpp"

#include <doctest/doctest.h>

#include <fstream>
#include <iterator>
#include <string>

using namespace sister_sign;
using namespace sister_sign::manifest;

namespace {

std::string fixture(const std::string& name) {
  std::ifstream f(std::string(SISTER_SIGN_FIXTURE_DIR) + "/manifest/" + name, std::ios::binary);
  REQUIRE_MESSAGE(f.good(), "fixture tidak ada: " << name);
  return std::string(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
}

const std::string kKey(64, 'a');
const std::string kSha(64, 'b');

Manifest sample() {
  Manifest m;
  m.package = "demo-pkg";
  m.version = "1.2.3";
  m.algorithm = "ed25519";
  m.keyid = kKey;
  m.artifact = ArtifactInfo{"app.tar.gz", 12345, kSha};
  return m;
}

// Bangun JSON manifest kanonik dengan potongan yang bisa diganti.
std::string canon(const std::string& schema = "minisign-manifest/v1",
                  const std::string& size = "12345", const std::string& name = "app.tar.gz") {
  return R"({"schema":")" + schema + R"(","package":"demo-pkg","version":"1.2.3",)" +
         R"("algorithm":"ed25519","keyid":")" + kKey + R"(","artifact":{"name":")" + name +
         R"(","size":)" + size + R"(,"sha256":")" + kSha + R"("}})";
}

void rejects(const std::string& json) {
  INFO(json);
  auto r = parse(json);
  REQUIRE_FALSE(r.has_value());
  CHECK(r.error().status == Status::FormatError);
}

}  // namespace

TEST_CASE("manifest: golden file byte-exact") {
  for (const char* name : {"basic.json", "size_zero.json", "size_max.json"}) {
    INFO(name);
    std::string golden = fixture(name);
    auto m = parse(golden);
    REQUIRE(m.has_value());
    auto out = serialize(*m);
    REQUIRE(out.has_value());
    CHECK(*out == golden);
  }
}

TEST_CASE("manifest: batas size 0 dan 2^53-1") {
  CHECK(parse(fixture("size_zero.json"))->artifact.size == 0);
  CHECK(parse(fixture("size_max.json"))->artifact.size == 9007199254740991ULL);
}

TEST_CASE("manifest: serialize tanpa whitespace dan newline") {
  auto out = serialize(sample());
  REQUIRE(out.has_value());
  CHECK(out->find(' ') == std::string::npos);
  CHECK(out->find('\n') == std::string::npos);
  CHECK(out->find('\r') == std::string::npos);
  CHECK(out->find('\t') == std::string::npos);
  CHECK(*out == canon());
}

TEST_CASE("manifest: serialize menolak field di luar aturan") {
  auto bad = [](auto mutate) {
    Manifest m = sample();
    mutate(m);
    auto r = serialize(m);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().status == Status::FormatError);
  };
  bad([](Manifest& m) { m.package = "Bad Name"; });
  bad([](Manifest& m) { m.package = ""; });
  bad([](Manifest& m) { m.version = "1 2"; });
  bad([](Manifest& m) { m.algorithm = "ED25519"; });
  bad([](Manifest& m) { m.keyid = std::string(63, 'a'); });
  bad([](Manifest& m) { m.keyid = std::string(64, 'A'); });
  bad([](Manifest& m) { m.artifact.name = "../x"; });
  bad([](Manifest& m) { m.artifact.name = ".."; });
  bad([](Manifest& m) { m.artifact.name = "caf\xC3\xA9"; });  // non-ASCII
  bad([](Manifest& m) { m.artifact.name = "a\"b"; });         // butuh escape
  bad([](Manifest& m) { m.artifact.size = kMaxSize + 1; });
  bad([](Manifest& m) { m.artifact.sha256 = "xyz"; });
}

TEST_CASE("manifest: roundtrip parse -> serialize identik") {
  auto m = parse(canon());
  REQUIRE(m.has_value());
  CHECK(m->package == "demo-pkg");
  CHECK(m->version == "1.2.3");
  CHECK(m->algorithm == "ed25519");
  CHECK(m->keyid == kKey);
  CHECK(m->artifact.name == "app.tar.gz");
  CHECK(m->artifact.size == 12345);
  CHECK(m->artifact.sha256 == kSha);
  CHECK(*serialize(*m) == canon());
}

TEST_CASE("manifest: algoritma tak dikenal tetap lolos parse (ditolak di verify)") {
  std::string j = canon();
  j.replace(j.find("ed25519"), 7, "rsa-pss-2048");
  auto m = parse(j);
  REQUIRE(m.has_value());
  crypto::Algorithm a;
  CHECK_FALSE(parse_algorithm_name(m->algorithm, a));
}

TEST_CASE("manifest: nama algoritma <-> enum") {
  for (auto a :
       {crypto::Algorithm::RsaPss, crypto::Algorithm::EcdsaP256, crypto::Algorithm::Ed25519}) {
    crypto::Algorithm back;
    REQUIRE(parse_algorithm_name(algorithm_name(a), back));
    CHECK(back == a);
  }
}

TEST_CASE("manifest: key ganda") { rejects(R"({"a":1,"a":2})"); }

TEST_CASE("manifest: key ganda di manifest utuh") {
  std::string j = canon();
  j.insert(j.size() - 1, R"(,"package":"demo-pkg")");
  rejects(j);
  std::string k = canon();
  k.insert(k.size() - 2, R"(,"size":1)");
  rejects(k);
}

TEST_CASE("manifest: field tambahan") {
  std::string j = canon();
  j.insert(j.size() - 1, R"(,"extra":1)");
  rejects(j);
  std::string k = canon();
  k.insert(k.size() - 2, R"(,"extra":1)");
  rejects(k);  // artifact != tepat 3 field
}

TEST_CASE("manifest: field kurang") {
  rejects(R"({"schema":"minisign-manifest/v1"})");
  std::string j = canon();
  auto pos = j.find(R"(,"sha256")");
  j.erase(pos, j.size() - pos - 2);
  rejects(j);  // artifact hanya 2 field
}

TEST_CASE("manifest: urutan field terbalik") {
  rejects(R"({"package":"demo-pkg","schema":"minisign-manifest/v1","version":"1.2.3",)"
          R"("algorithm":"ed25519","keyid":")" +
          kKey + R"(","artifact":{"name":"app.tar.gz","size":1,"sha256":")" + kSha + R"("}})");
  rejects(R"({"schema":"minisign-manifest/v1","package":"demo-pkg","version":"1.2.3",)"
          R"("algorithm":"ed25519","keyid":")" +
          kKey + R"(","artifact":{"size":1,"name":"app.tar.gz","sha256":")" + kSha + R"("}})");
}

TEST_CASE("manifest: whitespace nyasar") {
  std::string j = canon();
  rejects(" " + j);
  rejects(j + " ");
  rejects(j + "\n");
  std::string k = canon();
  k.insert(k.find(':'), " ");
  rejects(k);
  std::string l = canon();
  l.replace(l.find(','), 1, ", ");
  rejects(l);
}

TEST_CASE("manifest: BOM di awal") { rejects("\xEF\xBB\xBF" + canon()); }

TEST_CASE("manifest: size bentuk salah") {
  rejects(canon("minisign-manifest/v1", "true"));
  rejects(canon("minisign-manifest/v1", "false"));
  rejects(canon("minisign-manifest/v1", "1.0"));
  rejects(canon("minisign-manifest/v1", "01"));
  rejects(canon("minisign-manifest/v1", "+1"));
  rejects(canon("minisign-manifest/v1", "1e2"));
  rejects(canon("minisign-manifest/v1", "-1"));
  rejects(canon("minisign-manifest/v1", "\"12\""));
  rejects(canon("minisign-manifest/v1", "9007199254740992"));  // 2^53
  rejects(canon("minisign-manifest/v1", "99999999999999999999"));
  rejects(canon("minisign-manifest/v1", "null"));
}

TEST_CASE("manifest: null dan tipe salah") {
  rejects(R"({"schema":null})");
  std::string j = canon();
  j.replace(j.find(R"("demo-pkg")"), 10, "null");
  rejects(j);
  std::string k = canon();
  k.replace(k.find(R"("demo-pkg")"), 10, "123");
  rejects(k);
  std::string l = canon();
  l.replace(l.find(R"({"name")"), l.size() - l.find(R"({"name")") - 1, "[]");
  rejects(l);  // artifact bukan objek
  rejects("[]");
  rejects("\"x\"");
  rejects("");
}

TEST_CASE("manifest: escape \\u dan karakter non-ASCII") {
  std::string j = canon();
  j.replace(j.find("demo-pkg"), 8, "demo-pk\\u0067");  // "g" lewat escape
  rejects(j);
  rejects(canon("minisign-manifest/v1", "1", "caf\xC3\xA9"));
  rejects(canon("minisign-manifest/v1", "1", "a\\\"b"));
  rejects(canon("minisign-manifest/v1", "1", "a\\/b"));
}

TEST_CASE("manifest: schema salah") {
  rejects(canon("minisign-manifest/v2"));
  rejects(canon("minisign-bundle/v1"));
  rejects(canon(""));
}

TEST_CASE("manifest: pola field di parse") {
  rejects(canon("minisign-manifest/v1", "1", "../etc"));
  rejects(canon("minisign-manifest/v1", "1", ".."));
  rejects(canon("minisign-manifest/v1", "1", ""));
  rejects(canon("minisign-manifest/v1", "1", "a b"));
  std::string j = canon();
  j.replace(j.find("demo-pkg"), 8, "Demo-Pkg");  // huruf besar tak boleh di package
  rejects(j);
  std::string k = canon();
  k.replace(k.find(kKey), 64, std::string(64, 'A'));  // hex besar
  rejects(k);
  std::string l = canon();
  l.replace(l.find(kSha), 64, std::string(63, 'b'));  // pendek
  rejects(l);
}

TEST_CASE("manifest: lebih dari 16 KiB") {
  std::string j = canon();
  j.insert(j.size() - 1, "," + std::string(kMaxManifestBytes, ' '));
  rejects(j);
  rejects(std::string(kMaxManifestBytes + 1, 'x'));
}

TEST_CASE("manifest: validator") {
  CHECK(valid_package("a"));
  CHECK(valid_package("my-pkg_1.0"));
  CHECK_FALSE(valid_package("-a"));
  CHECK_FALSE(valid_package(std::string(65, 'a')));
  CHECK(valid_version("1.0.0-rc.1+build5"));
  CHECK_FALSE(valid_version("+1"));
  CHECK(valid_artifact_name("a.b-c_d"));
  CHECK_FALSE(valid_artifact_name("."));
  CHECK_FALSE(valid_artifact_name(std::string(256, 'a')));
  CHECK(valid_hex64(std::string(64, '0')));
  CHECK_FALSE(valid_hex64(std::string(64, 'g')));
}
