#include "verify/verify.hpp"

#include <doctest/doctest.h>
#include <unistd.h>

#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <string>
#include <vector>

#include "bundle/bundle.hpp"
#include "crypto/keyio.hpp"
#include "manifest/manifest.hpp"
#include "trust/trust.hpp"
#include "util/hash.hpp"
#include "util/hex.hpp"

using namespace sister_sign;
using crypto::Algorithm;
namespace fs = std::filesystem;

namespace {

struct TempDir {
  fs::path path;
  TempDir() {
    std::string tmpl = (fs::temp_directory_path() / "verify_test_XXXXXX").string();
    REQUIRE(::mkdtemp(tmpl.data()) != nullptr);
    path = tmpl;
  }
  ~TempDir() {
    std::error_code ec;
    fs::remove_all(path, ec);
  }
};

void spit(const fs::path& p, const std::string& data) {
  std::ofstream(p, std::ios::binary) << data;
}

std::string slurp(const fs::path& p) {
  std::ifstream f(p, std::ios::binary);
  return std::string(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
}

Bytes to_bytes(const std::string& s) { return Bytes(s.begin(), s.end()); }

std::string sha_hex(const std::string& data) {
  return util::hex_lower(
      *util::sha256(ByteView(reinterpret_cast<const std::uint8_t*>(data.data()), data.size())));
}

// Kunci di-cache (RSA 3072 lambat). `other` adalah kunci kedua untuk tiap algoritma.
struct TestKey {
  crypto::PrivateKey priv;
  crypto::PublicKey pub;
  std::string keyid;
};

TestKey make_key(Algorithm a) {
  auto kp = crypto::generate_keypair(a);
  REQUIRE(kp.has_value());
  std::string id = *crypto::keyid(kp->pub);
  return TestKey{std::move(kp->priv), std::move(kp->pub), std::move(id)};
}

const TestKey& key(Algorithm a, int slot = 0) {
  static std::vector<std::pair<std::pair<Algorithm, int>, TestKey>> cache;
  for (const auto& e : cache) {
    if (e.first.first == a && e.first.second == slot) return e.second;
  }
  cache.emplace_back(std::make_pair(a, slot), make_key(a));
  return cache.back().second;
}

const std::string kContent = "isi artefak\n";

// Satu skenario verify lengkap di direktori sementara. Semua bagian bisa diubah sebelum dijalankan.
struct Scenario {
  TempDir dir;
  const TestKey* signer = &key(Algorithm::Ed25519);
  std::string package = "demo";
  std::string version = "1.0.0";
  std::string content = kContent;
  std::string name = "app.bin";

  manifest::Manifest m;
  Bytes manifest_bytes;
  Bytes signature;

  fs::path file() const { return dir.path / name; }
  fs::path bundle() const { return dir.path / "b.json"; }
  fs::path store() const { return dir.path / "t.json"; }

  Scenario() { rebuild(); }

  // Susun manifest dari field saat ini lalu tanda tangani dengan `signer`.
  void rebuild() {
    m = manifest::Manifest{};
    m.package = package;
    m.version = version;
    m.algorithm = std::string(manifest::algorithm_name(signer->priv.algorithm()));
    m.keyid = signer->keyid;
    m.artifact = manifest::ArtifactInfo{name, content.size(), sha_hex(content)};
    resign();
    write_artifact();
    write_store({{signer, package}});
  }

  void resign() {
    auto text = manifest::serialize(m);
    REQUIRE(text.has_value());
    manifest_bytes = to_bytes(*text);
    auto sig = crypto::sign(signer->priv, manifest_bytes);
    REQUIRE(sig.has_value());
    signature = *sig;
    write_bundle();
  }

  void write_bundle() {
    auto text = bundle::write(bundle::Bundle{manifest_bytes, signature});
    REQUIRE(text.has_value());
    spit(bundle(), *text);
  }

  void write_artifact() { spit(file(), content); }

  void write_store(const std::vector<std::pair<const TestKey*, std::string>>& entries) {
    trust::TrustStore s;
    for (const auto& [k, pkg] : entries) REQUIRE(s.add(k->pub, pkg).has_value());
    REQUIRE(s.save(store()).has_value());
  }

  Result run() const { return verifier::verify(file(), bundle(), store(), package, version); }
};

void expect(const Result& r, Status s) {
  INFO(r.message);
  CHECK(r.status == s);
  CHECK(r.valid == (s == Status::Ok));
}

}  // namespace

// ---- OK ----------------------------------------------------------------------------------------

TEST_CASE("verify: OK untuk tiga algoritma") {
  for (auto a : {Algorithm::Ed25519, Algorithm::EcdsaP256, Algorithm::RsaPss}) {
    Scenario s;
    s.signer = &key(a);
    s.rebuild();
    auto r = s.run();
    INFO(manifest::algorithm_name(a));
    expect(r, Status::Ok);
    CHECK(r.algorithm == manifest::algorithm_name(a));
    CHECK(r.keyid == s.signer->keyid);
    CHECK(r.package == "demo");
    CHECK(r.version == "1.0.0");
  }
}

TEST_CASE("verify: OK untuk artefak kosong, biner, dan besar") {
  std::string binary;
  for (int i = 0; i < 256; ++i) binary.push_back(static_cast<char>(i));
  std::string big(64 * 1024 * 2 + 17, 'x');
  for (const std::string& content : {std::string(), binary, big}) {
    Scenario s;
    s.content = content;
    s.rebuild();
    expect(s.run(), Status::Ok);
  }
}

TEST_CASE("verify: path artefak dengan direktori, dibandingkan lewat basename") {
  Scenario s;
  fs::create_directory(s.dir.path / "sub");
  spit(s.dir.path / "sub" / s.name, s.content);
  auto r = verifier::verify(s.dir.path / "sub" / s.name, s.bundle(), s.store(), "demo", "1.0.0");
  expect(r, Status::Ok);
}

TEST_CASE("verify: bundle di-reformat (urutan field, spasi, newline) tetap OK") {
  Scenario s;
  auto text = bundle::write(bundle::Bundle{s.manifest_bytes, s.signature});
  const std::string& t = *text;
  // Ambil dua nilai base64 dari bundle kanonik dan susun ulang dengan urutan/whitespace lain.
  auto value_of = [&](const std::string& field) {
    auto p = t.find("\"" + field + "\":\"") + field.size() + 4;
    return t.substr(p, t.find('"', p) - p);
  };
  spit(s.bundle(), "{\n  \"signature_b64\" : \"" + value_of("signature_b64") +
                       "\",\n\t\"schema\":\"minisign-bundle/v1\",\r\n \"manifest_b64\":\"" +
                       value_of("manifest_b64") + "\"\n}\n");
  expect(s.run(), Status::Ok);
}

// ---- satu test per status ----------------------------------------------------------------------

TEST_CASE("verify: INPUT_ERROR") {
  Scenario s;
  SUBCASE("artefak tidak ada") {
    fs::remove(s.file());
    expect(s.run(), Status::InputError);
  }
  SUBCASE("artefak berupa direktori") {
    fs::remove(s.file());
    fs::create_directory(s.file());
    expect(s.run(), Status::InputError);
  }
  SUBCASE("bundle tidak ada") {
    fs::remove(s.bundle());
    expect(s.run(), Status::InputError);
  }
  SUBCASE("trust store tidak ada") {
    fs::remove(s.store());
    expect(s.run(), Status::InputError);
  }
}

TEST_CASE("verify: FORMAT_ERROR") {
  Scenario s;
  SUBCASE("bundle bukan JSON") {
    spit(s.bundle(), "bukan json");
    expect(s.run(), Status::FormatError);
  }
  SUBCASE("bundle dengan field tambahan") {
    auto t = *bundle::write(bundle::Bundle{s.manifest_bytes, s.signature});
    t.insert(t.size() - 1, ",\"extra\":1");
    spit(s.bundle(), t);
    expect(s.run(), Status::FormatError);
  }
  SUBCASE("manifest tidak kanonik meski ditandatangani sah") {
    std::string spaced(s.manifest_bytes.begin(), s.manifest_bytes.end());
    spaced.insert(1, " ");
    s.manifest_bytes = to_bytes(spaced);
    s.signature = *crypto::sign(s.signer->priv, s.manifest_bytes);
    s.write_bundle();
    expect(s.run(), Status::FormatError);
  }
  SUBCASE("manifest rusak") {
    s.manifest_bytes = to_bytes("{}");
    s.signature = *crypto::sign(s.signer->priv, s.manifest_bytes);
    s.write_bundle();
    expect(s.run(), Status::FormatError);
  }
  SUBCASE("trust store rusak") {
    spit(s.store(), "{bukan json");
    expect(s.run(), Status::FormatError);
  }
  SUBCASE("trust store dengan fingerprint tidak cocok") {
    auto t = slurp(s.store());
    auto p = t.find(s.signer->keyid);
    REQUIRE(p != std::string::npos);
    t[p] = (t[p] == '0') ? '1' : '0';
    spit(s.store(), t);
    expect(s.run(), Status::FormatError);
  }
}

TEST_CASE("verify: UNSUPPORTED_ALGORITHM") {
  Scenario s;
  for (const char* alg : {"rsa-pss-2048", "ed448", "md5-rsa"}) {
    INFO(alg);
    s.m.algorithm = alg;
    s.resign();
    expect(s.run(), Status::UnsupportedAlgorithm);
  }
}

TEST_CASE("verify: KEY_NOT_TRUSTED") {
  Scenario s;
  SUBCASE("trust store kosong") {
    s.write_store({});
    expect(s.run(), Status::KeyNotTrusted);
  }
  SUBCASE("kunci lain yang dipercaya") {
    s.write_store({{&key(Algorithm::Ed25519, 1), "demo"}});
    expect(s.run(), Status::KeyNotTrusted);
  }
  SUBCASE("keyid dipercaya hanya untuk package lain") {
    s.write_store({{s.signer, "lain"}});
    expect(s.run(), Status::KeyNotTrusted);
  }
  SUBCASE("profil di manifest berbeda dari profil kunci di store") {
    s.m.algorithm = "ecdsa-p256";  // keyid milik kunci Ed25519
    s.resign();
    expect(s.run(), Status::KeyNotTrusted);
  }
}

TEST_CASE("verify: INVALID_SIGNATURE") {
  Scenario s;
  SUBCASE("satu bit signature dibalik") {
    s.signature[0] ^= 1;
    s.write_bundle();
    expect(s.run(), Status::InvalidSignature);
  }
  SUBCASE("signature panjang salah") {
    s.signature.pop_back();
    s.write_bundle();
    expect(s.run(), Status::InvalidSignature);
    s.signature.assign(200, 0);
    s.write_bundle();
    expect(s.run(), Status::InvalidSignature);
    s.signature.clear();
    s.write_bundle();
    expect(s.run(), Status::InvalidSignature);
  }
  SUBCASE("manifest diganti setelah ditandatangani") {
    s.m.artifact.size += 1;
    auto other = manifest::serialize(s.m);
    s.manifest_bytes = to_bytes(*other);  // signature lama tetap
    s.write_bundle();
    expect(s.run(), Status::InvalidSignature);
  }
  SUBCASE("ditandatangani kunci lain tetapi mengaku keyid kunci terpercaya") {
    // Kedua kunci ada di trust store; tidak boleh ada fallback ke kunci lain.
    const TestKey& other = key(Algorithm::Ed25519, 1);
    s.write_store({{s.signer, "demo"}, {&other, "demo"}});
    s.signature = *crypto::sign(other.priv, s.manifest_bytes);
    s.write_bundle();
    expect(s.run(), Status::InvalidSignature);
  }
}

TEST_CASE("verify: METADATA_MISMATCH") {
  Scenario s;
  SUBCASE("package berbeda") {
    s.package = "lain";  // masukan pengguna; manifest tetap "demo"
    auto r = s.run();
    expect(r, Status::MetadataMismatch);
    CHECK(r.package == "demo");  // sudah terotentikasi
  }
  SUBCASE("version berbeda") {
    s.version = "2.0.0";
    expect(s.run(), Status::MetadataMismatch);
  }
  SUBCASE("nama berkas berbeda dari artifact.name") {
    fs::rename(s.file(), s.dir.path / "ganti.bin");
    auto r = verifier::verify(s.dir.path / "ganti.bin", s.bundle(), s.store(), "demo", "1.0.0");
    expect(r, Status::MetadataMismatch);
  }
}

TEST_CASE("verify: ARTIFACT_MISMATCH") {
  Scenario s;
  SUBCASE("ukuran berbeda") {
    s.content += "tambahan";
    s.write_artifact();
    expect(s.run(), Status::ArtifactMismatch);
  }
  SUBCASE("ukuran sama, isi berbeda (SHA-256)") {
    s.content[0] ^= 1;
    s.write_artifact();
    auto r = s.run();
    expect(r, Status::ArtifactMismatch);
    CHECK(r.message.find("SHA-256") != std::string::npos);
  }
  SUBCASE("artefak dipotong jadi kosong") {
    spit(s.file(), "");
    expect(s.run(), Status::ArtifactMismatch);
  }
}

// ---- prioritas dan stop-at-first-failure -------------------------------------------------------

TEST_CASE("verify: INPUT_ERROR mengalahkan semua yang lain") {
  Scenario s;
  spit(s.bundle(), "bukan json");  // FORMAT_ERROR kalau dibaca
  fs::remove(s.file());
  expect(s.run(), Status::InputError);
}

TEST_CASE("verify: format salah + trust store kosong -> FORMAT_ERROR") {
  Scenario s;
  spit(s.bundle(), "bukan json");
  s.write_store({});
  expect(s.run(), Status::FormatError);
}

TEST_CASE("verify: format salah + metadata salah -> FORMAT_ERROR") {
  Scenario s;
  spit(s.bundle(), "{}");
  s.version = "9";
  expect(s.run(), Status::FormatError);
}

TEST_CASE("verify: algoritma tak didukung + trust store kosong -> UNSUPPORTED_ALGORITHM") {
  Scenario s;
  s.m.algorithm = "ed448";
  s.resign();
  s.write_store({});
  expect(s.run(), Status::UnsupportedAlgorithm);
}

TEST_CASE("verify: kunci tak dipercaya + signature rusak -> KEY_NOT_TRUSTED") {
  Scenario s;
  s.signature[0] ^= 1;
  s.write_bundle();
  s.write_store({});
  expect(s.run(), Status::KeyNotTrusted);
}

TEST_CASE("verify: signature salah + versi salah -> INVALID_SIGNATURE") {
  Scenario s;
  s.signature[0] ^= 1;
  s.write_bundle();
  s.version = "9.9.9";
  expect(s.run(), Status::InvalidSignature);
}

TEST_CASE("verify: signature salah + artefak berubah -> INVALID_SIGNATURE") {
  Scenario s;
  s.signature[0] ^= 1;
  s.write_bundle();
  s.content += "x";
  s.write_artifact();
  expect(s.run(), Status::InvalidSignature);
}

TEST_CASE("verify: metadata salah + artefak berubah -> METADATA_MISMATCH") {
  Scenario s;
  s.content += "x";
  s.write_artifact();
  s.package = "lain";
  expect(s.run(), Status::MetadataMismatch);
}

TEST_CASE("verify: kegagalan sebelum signature tidak membocorkan isi manifest") {
  Scenario s;
  s.write_store({});
  auto r = s.run();
  expect(r, Status::KeyNotTrusted);
  CHECK(r.keyid.empty());
  CHECK(r.package.empty());
  CHECK(r.version.empty());
  CHECK(r.algorithm.empty());
}

TEST_CASE("verify: bundle tidak bisa menambah trust (kunci hanya dari store)") {
  // Bundle tidak punya tempat untuk pubkey; manifest yang ditandatangani kunci tak dikenal ditolak.
  Scenario s;
  const TestKey& stranger = key(Algorithm::Ed25519, 1);
  s.signer = &stranger;
  s.m.keyid = stranger.keyid;
  s.resign();
  s.write_store({{&key(Algorithm::Ed25519, 0), "demo"}});
  expect(s.run(), Status::KeyNotTrusted);
}

TEST_CASE("verify: tidak ada efek samping pada berkas masukan") {
  Scenario s;
  const auto b = slurp(s.bundle());
  const auto t = slurp(s.store());
  const auto f = slurp(s.file());
  s.run();
  s.signature[0] ^= 1;
  s.write_bundle();
  const auto b2 = slurp(s.bundle());
  s.run();
  CHECK(slurp(s.bundle()) == b2);
  CHECK(slurp(s.store()) == t);
  CHECK(slurp(s.file()) == f);
  CHECK(b != b2);
}
