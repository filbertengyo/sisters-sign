#include "bundle/bundle.hpp"

#include <doctest/doctest.h>

#include <fstream>
#include <iterator>
#include <string>

#include "util/base64.hpp"

using namespace sister_sign;
using namespace sister_sign::bundle;

namespace {

Bytes bytes_of(std::string_view s) { return Bytes(s.begin(), s.end()); }

std::string fixture(const std::string& name) {
  std::ifstream f(std::string(SISTER_SIGN_FIXTURE_DIR) + "/bundle/" + name, std::ios::binary);
  REQUIRE_MESSAGE(f.good(), "fixture tidak ada: " << name);
  return std::string(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
}

void rejects(const std::string& json) {
  INFO(json.substr(0, 200));
  auto r = read(json);
  REQUIRE_FALSE(r.has_value());
  CHECK(r.error().status == Status::FormatError);
}

const std::string kM = "aGVsbG8=";  // "hello"
const std::string kS = "AAECAw==";  // 00 01 02 03

std::string make(const std::string& schema = "minisign-bundle/v1", const std::string& m = kM,
                 const std::string& s = kS) {
  return R"({"schema":")" + schema + R"(","manifest_b64":")" + m + R"(","signature_b64":")" + s +
         R"("})";
}

}  // namespace

TEST_CASE("bundle: roundtrip write -> read, M identik byte-per-byte") {
  Bundle b{bytes_of(R"({"schema":"x"})"), Bytes{0, 1, 2, 0xFF, 0x80}};
  auto text = write(b);
  REQUIRE(text.has_value());
  auto back = read(*text);
  REQUIRE(back.has_value());
  CHECK(back->manifest == b.manifest);
  CHECK(back->signature == b.signature);
}

TEST_CASE("bundle: M biner dan kosong dibawa apa adanya") {
  Bytes raw;
  for (int i = 0; i < 256; ++i) raw.push_back(static_cast<std::uint8_t>(i));
  auto back = read(*write(Bundle{raw, {}}));
  REQUIRE(back.has_value());
  CHECK(back->manifest == raw);
  CHECK(back->signature.empty());
}

TEST_CASE("bundle: format tulis") {
  auto text = write(Bundle{bytes_of("hello"), Bytes{0, 1, 2, 3}});
  REQUIRE(text.has_value());
  CHECK(*text == make());
}

TEST_CASE("bundle: reformat (urutan, spasi, newline) tidak mengubah M dan sig") {
  auto a = read(make());
  auto b = read(fixture("reformatted.json"));
  REQUIRE(a.has_value());
  REQUIRE(b.has_value());
  CHECK(a->manifest == bytes_of("hello"));
  CHECK(b->manifest == a->manifest);
  CHECK(b->signature == a->signature);

  auto c = read(R"({"signature_b64":")" + kS + R"(","manifest_b64":")" + kM +
                R"(","schema":"minisign-bundle/v1"})");
  REQUIRE(c.has_value());
  CHECK(c->manifest == a->manifest);
}

TEST_CASE("bundle: field tambahan ditolak") {
  std::string j = make();
  j.insert(j.size() - 1, R"(,"extra":1)");
  rejects(j);
  std::string k = make();
  k.insert(k.size() - 1, R"(,"private_key":"-----BEGIN PRIVATE KEY-----")");
  rejects(k);
}

TEST_CASE("bundle: field kurang ditolak") {
  rejects(R"({"schema":"minisign-bundle/v1","manifest_b64":"aGVsbG8="})");
  rejects(R"({"schema":"minisign-bundle/v1","signature_b64":"AAECAw=="})");
  rejects(R"({"manifest_b64":"aGVsbG8=","signature_b64":"AAECAw=="})");
  rejects("{}");
}

TEST_CASE("bundle: key ganda ditolak") {
  std::string j = make();
  j.insert(j.size() - 1, R"(,"schema":"minisign-bundle/v1")");
  rejects(j);
  std::string k = make();
  k.insert(k.size() - 1, R"(,"signature_b64":"AAAA")");
  rejects(k);
  rejects(R"({"schema":"minisign-bundle/v1","manifest_b64":"aGVsbG8=","manifest_b64":"aGVsbG8=",)"
          R"("signature_b64":"AAECAw=="})");
}

TEST_CASE("bundle: base64 tidak valid ditolak") {
  rejects(make("minisign-bundle/v1", "aGVsbG8"));     // tanpa padding
  rejects(make("minisign-bundle/v1", "aGVs bG8="));   // whitespace
  rejects(make("minisign-bundle/v1", "aGVsbG8=\n"));  // newline ter-escape
  rejects(make("minisign-bundle/v1", "aGVsbG9="));    // trailing bits tidak nol
  rejects(make("minisign-bundle/v1", "a-Vs_G8="));    // url-safe
  rejects(make("minisign-bundle/v1", kM, "AAECAw"));
  rejects(make("minisign-bundle/v1", kM, "AAEC*w=="));
}

TEST_CASE("bundle: tipe salah dan null ditolak") {
  rejects(R"({"schema":"minisign-bundle/v1","manifest_b64":null,"signature_b64":"AAECAw=="})");
  rejects(R"({"schema":"minisign-bundle/v1","manifest_b64":1,"signature_b64":"AAECAw=="})");
  rejects(
      R"({"schema":"minisign-bundle/v1","manifest_b64":"aGVsbG8=","signature_b64":["AAECAw=="]})");
  rejects(R"({"schema":1,"manifest_b64":"aGVsbG8=","signature_b64":"AAECAw=="})");
  rejects("[]");
  rejects("\"x\"");
  rejects("");
}

TEST_CASE("bundle: schema salah ditolak") {
  rejects(make("minisign-bundle/v2"));
  rejects(make("minisign-manifest/v1"));
  rejects(make(""));
}

TEST_CASE("bundle: BOM dan sisa data ditolak") {
  rejects("\xEF\xBB\xBF" + make());
  rejects(make() + "x");
  rejects(make() + make());
}

TEST_CASE("bundle: lebih dari 64 KiB ditolak") {
  rejects(make() + std::string(kMaxBundleBytes, ' '));
  Bundle huge{Bytes(kMaxBundleBytes, 'a'), {}};
  auto w = write(huge);
  REQUIRE_FALSE(w.has_value());
  CHECK(w.error().status == Status::FormatError);
}

TEST_CASE("bundle: tepat di batas 64 KiB masih diterima") {
  std::string j = make();
  j.insert(j.size() - 1, std::string(kMaxBundleBytes - j.size(), ' '));
  REQUIRE(j.size() == kMaxBundleBytes);
  CHECK(read(j).has_value());
}
