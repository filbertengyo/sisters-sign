#include "trust/trust.hpp"

#include <doctest/doctest.h>
#include <unistd.h>

#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>

#include "crypto/keyio.hpp"
#include "manifest/manifest.hpp"

using namespace sister_sign;
using namespace sister_sign::trust;
using crypto::Algorithm;

namespace fs = std::filesystem;

namespace {

struct TestKey {
  crypto::PublicKey pub;
  std::string pem;
  std::string id;
};

TestKey make_key(Algorithm a) {
  auto kp = crypto::generate_keypair(a);
  REQUIRE(kp.has_value());
  auto pem = crypto::public_key_to_pem(kp->pub);
  auto id = crypto::keyid(kp->pub);
  REQUIRE(pem.has_value());
  REQUIRE(id.has_value());
  return TestKey{std::move(kp->pub), std::move(*pem), std::move(*id)};
}

// RSA 3072 butuh beberapa detik; buat sekali.
const TestKey& rsa_key() {
  static const TestKey k = make_key(Algorithm::RsaPss);
  return k;
}
const TestKey& ed_key() {
  static const TestKey k = make_key(Algorithm::Ed25519);
  return k;
}
const TestKey& ec_key() {
  static const TestKey k = make_key(Algorithm::EcdsaP256);
  return k;
}

std::string json_escape(const std::string& s) {
  std::string out;
  for (char c : s) {
    if (c == '\n') {
      out += "\\n";
    } else if (c == '"' || c == '\\') {
      out += '\\';
      out += c;
    } else {
      out += c;
    }
  }
  return out;
}

std::string entry_json(const std::string& keyid, const std::string& alg, const std::string& pem,
                       const std::string& packages = R"(["demo"])") {
  return R"({"keyid":")" + keyid + R"(","algorithm":")" + alg + R"(","public_key_pem":")" +
         json_escape(pem) + R"(","packages":)" + packages + "}";
}

std::string store_json(const std::string& entries,
                       const std::string& schema = "minisign-trust/v1") {
  return R"({"schema":")" + schema + R"(","keys":[)" + entries + "]}";
}

std::string good_entry(const TestKey& k, const std::string& alg,
                       const std::string& packages = R"(["demo"])") {
  return entry_json(k.id, alg, k.pem, packages);
}

void rejects(const std::string& json) {
  INFO(json.substr(0, 300));
  auto r = TrustStore::parse(json);
  REQUIRE_FALSE(r.has_value());
  CHECK(r.error().status == Status::FormatError);
}

struct TempDir {
  fs::path path;
  TempDir() {
    std::string tmpl = (fs::temp_directory_path() / "trust_test_XXXXXX").string();
    REQUIRE(::mkdtemp(tmpl.data()) != nullptr);
    path = tmpl;
  }
  ~TempDir() {
    std::error_code ec;
    fs::permissions(path, fs::perms::owner_all, ec);
    fs::remove_all(path, ec);
  }
};

std::string slurp(const fs::path& p) {
  std::ifstream f(p, std::ios::binary);
  return std::string(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
}

std::size_t count_files(const fs::path& dir) {
  std::size_t n = 0;
  for (auto it = fs::directory_iterator(dir); it != fs::directory_iterator(); ++it) ++n;
  return n;
}

}  // namespace

// ---- load / validasi ---------------------------------------------------------------------------

TEST_CASE("trust: store kosong sah dan tidak mempercayai siapa pun") {
  auto s = TrustStore::parse(store_json(""));
  REQUIRE(s.has_value());
  CHECK(s->entries().empty());
  auto r = s->lookup(ed_key().id, "demo", Algorithm::Ed25519);
  REQUIRE_FALSE(r.has_value());
  CHECK(r.error().status == Status::KeyNotTrusted);
  CHECK(TrustStore{}.lookup(ed_key().id, "demo", Algorithm::Ed25519).error().status ==
        Status::KeyNotTrusted);
}

TEST_CASE("trust: tiga algoritma dimuat dan lookup mengembalikan kunci") {
  const std::string json =
      store_json(good_entry(ed_key(), "ed25519") + "," + good_entry(ec_key(), "ecdsa-p256-sha256") +
                 "," + good_entry(rsa_key(), "rsa-pss-sha256"));
  auto s = TrustStore::parse(json);
  REQUIRE(s.has_value());
  CHECK(s->entries().size() == 3);

  auto ed = s->lookup(ed_key().id, "demo", Algorithm::Ed25519);
  REQUIRE(ed.has_value());
  CHECK((*ed)->algorithm() == Algorithm::Ed25519);
  CHECK(s->lookup(ec_key().id, "demo", Algorithm::EcdsaP256).has_value());
  CHECK(s->lookup(rsa_key().id, "demo", Algorithm::RsaPss).has_value());
}

TEST_CASE("trust: lookup menolak keyid asing, package asing, dan profil berbeda") {
  auto s = TrustStore::parse(store_json(good_entry(ed_key(), "ed25519")));
  REQUIRE(s.has_value());
  auto deny = [&](std::string_view id, std::string_view pkg, Algorithm a) {
    auto r = s->lookup(id, pkg, a);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().status == Status::KeyNotTrusted);
  };
  deny(ec_key().id, "demo", Algorithm::Ed25519);    // keyid asing
  deny(ed_key().id, "other", Algorithm::Ed25519);   // package asing
  deny(ed_key().id, "demo", Algorithm::EcdsaP256);  // profil beda dari manifest
  deny(ed_key().id, "demo", Algorithm::RsaPss);
  deny("", "demo", Algorithm::Ed25519);
  deny(std::string(64, '0'), "demo", Algorithm::Ed25519);
  deny(ed_key().id, "", Algorithm::Ed25519);
}

TEST_CASE("trust: pelanggaran struktur ditolak (FORMAT_ERROR)") {
  const std::string e = good_entry(ed_key(), "ed25519");

  SUBCASE("keyid ganda") { rejects(store_json(e + "," + e)); }
  SUBCASE("packages kosong") { rejects(store_json(good_entry(ed_key(), "ed25519", "[]"))); }
  SUBCASE("package ganda") { rejects(store_json(good_entry(ed_key(), "ed25519", R"(["a","a"])"))); }
  SUBCASE("wildcard") {
    rejects(store_json(good_entry(ed_key(), "ed25519", R"(["*"])")));
    rejects(store_json(good_entry(ed_key(), "ed25519", R"(["demo*"])")));
    rejects(store_json(good_entry(ed_key(), "ed25519", R"(["demo-?"])")));
  }
  SUBCASE("package di luar pola") {
    rejects(store_json(good_entry(ed_key(), "ed25519", R"([""])")));
    rejects(store_json(good_entry(ed_key(), "ed25519", R"(["Demo"])")));
  }
  SUBCASE("fingerprint tidak cocok") {
    rejects(store_json(entry_json(ec_key().id, "ed25519", ed_key().pem)));
    rejects(store_json(entry_json(std::string(64, '0'), "ed25519", ed_key().pem)));
  }
  SUBCASE("keyid bukan 64 hex huruf kecil") {
    std::string upper = ed_key().id;
    for (auto& c : upper) c = static_cast<char>(std::toupper(c));
    rejects(store_json(entry_json(upper, "ed25519", ed_key().pem)));
    rejects(store_json(entry_json("abc", "ed25519", ed_key().pem)));
  }
  SUBCASE("algoritma tidak cocok dengan kunci") {
    rejects(store_json(entry_json(ed_key().id, "ecdsa-p256-sha256", ed_key().pem)));
    rejects(store_json(entry_json(ec_key().id, "rsa-pss-sha256", ec_key().pem)));
  }
  SUBCASE("algoritma tak dikenal") {
    rejects(store_json(entry_json(ed_key().id, "ed448", ed_key().pem)));
  }
  SUBCASE("pubkey rusak") {
    rejects(store_json(entry_json(ed_key().id, "ed25519", "-----BEGIN PUBLIC KEY-----\nxx\n")));
    rejects(store_json(entry_json(ed_key().id, "ed25519", "")));
  }
  SUBCASE("PEM privkey di tempat pubkey") {
    rejects(store_json(entry_json(
        ed_key().id, "ed25519", "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")));
  }
  SUBCASE("field tambahan di entri") {
    std::string x = e;
    x.insert(x.size() - 1, R"(,"extra":1)");
    rejects(store_json(x));
  }
  SUBCASE("field tambahan di akar") {
    std::string j = store_json(e);
    j.insert(j.size() - 1, R"(,"extra":1)");
    rejects(j);
  }
  SUBCASE("field kurang") {
    rejects(R"({"schema":"minisign-trust/v1"})");
    rejects(R"({"keys":[]})");
    rejects(store_json(R"({"keyid":")" + ed_key().id + R"(","algorithm":"ed25519"})"));
  }
  SUBCASE("key ganda") {
    std::string j = store_json(e);
    j.insert(j.size() - 1, R"(,"keys":[])");
    rejects(j);
    std::string x = e;
    x.insert(x.size() - 1, R"(,"packages":["demo"])");
    rejects(store_json(x));
  }
  SUBCASE("tipe salah dan null") {
    rejects(R"({"schema":"minisign-trust/v1","keys":null})");
    rejects(R"({"schema":"minisign-trust/v1","keys":{}})");
    rejects(R"({"schema":"minisign-trust/v1","keys":[1]})");
    rejects(store_json(good_entry(ed_key(), "ed25519", R"("demo")")));
    rejects(store_json(good_entry(ed_key(), "ed25519", "[1]")));
    rejects(store_json(good_entry(ed_key(), "ed25519", "null")));
    rejects(store_json(
        R"({"keyid":1,"algorithm":"ed25519","public_key_pem":"x","packages":["demo"]})"));
  }
  SUBCASE("schema salah") {
    rejects(store_json(e, "minisign-trust/v2"));
    rejects(store_json(e, "minisign-bundle/v1"));
  }
  SUBCASE("sintaks rusak, BOM, kosong") {
    rejects("");
    rejects("{");
    rejects("\xEF\xBB\xBF" + store_json(e));
    rejects(store_json(e) + "x");
  }
  SUBCASE("terlalu besar") { rejects(store_json(e) + std::string(kMaxStoreBytes, ' ')); }
}

TEST_CASE("trust: urutan field dan whitespace bebas") {
  const auto& k = ed_key();
  std::string j = "{\n \"keys\" : [ {\n\"packages\":[\"demo\"],\"public_key_pem\":\"" +
                  json_escape(k.pem) + "\",\"algorithm\":\"ed25519\",\"keyid\":\"" + k.id +
                  "\"} ],\n \"schema\":\"minisign-trust/v1\" }\n";
  auto s = TrustStore::parse(j);
  REQUIRE(s.has_value());
  CHECK(s->lookup(k.id, "demo", Algorithm::Ed25519).has_value());
}

// ---- add / remove / list -----------------------------------------------------------------------

TEST_CASE("trust: add entri baru lalu lookup") {
  TrustStore s;
  REQUIRE(s.add(ed_key().pub, "demo").has_value());
  REQUIRE(s.entries().size() == 1);
  CHECK(s.entries()[0].keyid == ed_key().id);
  CHECK(s.entries()[0].algorithm == Algorithm::Ed25519);
  CHECK(s.lookup(ed_key().id, "demo", Algorithm::Ed25519).has_value());
}

TEST_CASE("trust: add idempoten") {
  TrustStore s;
  REQUIRE(s.add(ed_key().pub, "demo").has_value());
  auto once = s.to_json();
  REQUIRE(s.add(ed_key().pub, "demo").has_value());
  CHECK(s.entries().size() == 1);
  CHECK(s.entries()[0].packages.size() == 1);
  CHECK(*s.to_json() == *once);
}

TEST_CASE("trust: add package kedua memperbarui entri lama") {
  TrustStore s;
  REQUIRE(s.add(ed_key().pub, "demo").has_value());
  REQUIRE(s.add(ed_key().pub, "other").has_value());
  REQUIRE(s.entries().size() == 1);
  CHECK(s.entries()[0].packages == std::vector<std::string>{"demo", "other"});
  CHECK(s.lookup(ed_key().id, "other", Algorithm::Ed25519).has_value());
}

TEST_CASE("trust: add menolak package di luar pola (INPUT_ERROR)") {
  TrustStore s;
  for (const char* bad : {"", "*", "Demo", "a b", "../x"}) {
    INFO(bad);
    auto r = s.add(ed_key().pub, bad);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().status == Status::InputError);
  }
  CHECK(s.entries().empty());
}

TEST_CASE("trust: remove lalu lookup -> KEY_NOT_TRUSTED") {
  TrustStore s;
  REQUIRE(s.add(ed_key().pub, "demo").has_value());
  REQUIRE(s.add(ec_key().pub, "demo").has_value());
  REQUIRE(s.remove(ed_key().id).has_value());
  CHECK(s.entries().size() == 1);
  auto r = s.lookup(ed_key().id, "demo", Algorithm::Ed25519);
  REQUIRE_FALSE(r.has_value());
  CHECK(r.error().status == Status::KeyNotTrusted);
  CHECK(s.lookup(ec_key().id, "demo", Algorithm::EcdsaP256).has_value());
}

TEST_CASE("trust: remove keyid asing -> INPUT_ERROR") {
  TrustStore s;
  REQUIRE(s.add(ed_key().pub, "demo").has_value());
  auto r = s.remove(ec_key().id);
  REQUIRE_FALSE(r.has_value());
  CHECK(r.error().status == Status::InputError);
  CHECK(s.entries().size() == 1);
  CHECK_FALSE(s.remove("").has_value());
}

TEST_CASE("trust: to_json deterministik dan bisa di-parse ulang untuk tiga algoritma") {
  TrustStore a;
  REQUIRE(a.add(rsa_key().pub, "zeta").has_value());
  REQUIRE(a.add(ed_key().pub, "demo").has_value());
  REQUIRE(a.add(ec_key().pub, "demo").has_value());
  REQUIRE(a.add(ed_key().pub, "alpha").has_value());

  TrustStore b;  // urutan penambahan berbeda
  REQUIRE(b.add(ec_key().pub, "demo").has_value());
  REQUIRE(b.add(ed_key().pub, "alpha").has_value());
  REQUIRE(b.add(rsa_key().pub, "zeta").has_value());
  REQUIRE(b.add(ed_key().pub, "demo").has_value());

  auto ja = a.to_json();
  REQUIRE(ja.has_value());
  CHECK(*ja == *b.to_json());
  CHECK(ja->back() == '\n');

  auto back = TrustStore::parse(*ja);
  REQUIRE(back.has_value());
  CHECK(back->entries().size() == 3);
  CHECK(back->lookup(ed_key().id, "alpha", Algorithm::Ed25519).has_value());
  CHECK(back->lookup(rsa_key().id, "zeta", Algorithm::RsaPss).has_value());
  CHECK(*back->to_json() == *ja);
}

// ---- berkas ------------------------------------------------------------------------------------

TEST_CASE("trust: save lalu load") {
  TempDir d;
  const auto path = d.path / "trust.json";
  TrustStore s;
  REQUIRE(s.add(ed_key().pub, "demo").has_value());
  REQUIRE(s.save(path).has_value());
  CHECK(count_files(d.path) == 1);  // tidak ada temp file tersisa

  auto loaded = TrustStore::load(path);
  REQUIRE(loaded.has_value());
  CHECK(loaded->lookup(ed_key().id, "demo", Algorithm::Ed25519).has_value());
}

TEST_CASE("trust: add dua kali lewat berkas menghasilkan berkas identik") {
  TempDir d;
  const auto path = d.path / "trust.json";
  for (int i = 0; i < 2; ++i) {
    auto s = TrustStore::load_or_empty(path);
    REQUIRE(s.has_value());
    REQUIRE(s->add(ed_key().pub, "demo").has_value());
    REQUIRE(s->save(path).has_value());
  }
  const std::string once = slurp(path);
  auto s = TrustStore::load(path);
  REQUIRE(s.has_value());
  REQUIRE(s->add(ed_key().pub, "demo").has_value());
  REQUIRE(s->save(path).has_value());
  CHECK(slurp(path) == once);
}

TEST_CASE("trust: load_or_empty untuk berkas yang belum ada, load -> INPUT_ERROR") {
  TempDir d;
  auto e = TrustStore::load_or_empty(d.path / "none.json");
  REQUIRE(e.has_value());
  CHECK(e->entries().empty());
  auto r = TrustStore::load(d.path / "none.json");
  REQUIRE_FALSE(r.has_value());
  CHECK(r.error().status == Status::InputError);
}

TEST_CASE("trust: load berkas rusak -> FORMAT_ERROR") {
  TempDir d;
  const auto path = d.path / "trust.json";
  std::ofstream(path) << "{bukan json";
  auto r = TrustStore::load(path);
  REQUIRE_FALSE(r.has_value());
  CHECK(r.error().status == Status::FormatError);
  CHECK(TrustStore::load_or_empty(path).error().status == Status::FormatError);
}

TEST_CASE("trust: gagal tulis (direktori read-only) -> berkas lama utuh") {
  if (::geteuid() == 0) {
    MESSAGE("dilewati: root mengabaikan izin direktori");
    return;
  }
  TempDir d;
  const auto path = d.path / "trust.json";
  TrustStore s;
  REQUIRE(s.add(ed_key().pub, "demo").has_value());
  REQUIRE(s.save(path).has_value());
  const std::string before = slurp(path);

  REQUIRE(s.add(ec_key().pub, "demo").has_value());
  fs::permissions(d.path, fs::perms::owner_read | fs::perms::owner_exec);
  auto r = s.save(path);
  fs::permissions(d.path, fs::perms::owner_all);
  REQUIRE_FALSE(r.has_value());
  CHECK(r.error().status == Status::InputError);
  CHECK(slurp(path) == before);
  CHECK(count_files(d.path) == 1);
}

TEST_CASE("trust: gagal rename -> berkas sementara dibersihkan") {
  TempDir d;
  const auto target = d.path / "trust.json";
  fs::create_directory(target);  // rename file ke direktori yang ada pasti gagal
  std::ofstream(target / "keep") << "x";

  TrustStore s;
  REQUIRE(s.add(ed_key().pub, "demo").has_value());
  auto r = s.save(target);
  REQUIRE_FALSE(r.has_value());
  CHECK(r.error().status == Status::InputError);
  CHECK(count_files(d.path) == 1);
  CHECK(fs::exists(target / "keep"));
}

TEST_CASE("trust: save ke direktori yang tidak ada -> INPUT_ERROR") {
  TempDir d;
  TrustStore s;
  auto r = s.save(d.path / "tidak-ada" / "trust.json");
  REQUIRE_FALSE(r.has_value());
  CHECK(r.error().status == Status::InputError);
}
