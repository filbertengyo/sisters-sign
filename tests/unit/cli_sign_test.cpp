#include <doctest/doctest.h>
#include <unistd.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

#include "bundle/bundle.hpp"
#include "cli/cli.hpp"
#include "crypto/keyio.hpp"
#include "manifest/manifest.hpp"
#include "util/hash.hpp"
#include "util/hex.hpp"

using namespace sister_sign;
using namespace sister_sign::cli;
namespace fs = std::filesystem;

namespace {

struct Run {
  int code;
  std::string out;
  std::string err;
};

Run run_cli(std::vector<std::string_view> args) {
  std::ostringstream out, err;
  int code = run(args, Io{out, err});
  return Run{code, out.str(), err.str()};
}

struct TempDir {
  fs::path path;
  TempDir() {
    std::string tmpl = (fs::temp_directory_path() / "cli_sign_XXXXXX").string();
    REQUIRE(::mkdtemp(tmpl.data()) != nullptr);
    path = tmpl;
  }
  ~TempDir() {
    std::error_code ec;
    fs::permissions(path, fs::perms::owner_all, ec);
    fs::remove_all(path, ec);
  }
  std::string file(const std::string& name) const { return (path / name).string(); }
};

std::string slurp(const fs::path& p) {
  std::ifstream f(p, std::ios::binary);
  return std::string(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
}

void spit(const fs::path& p, const std::string& data) {
  std::ofstream(p, std::ios::binary) << data;
}

// Pasangan kunci di-cache (RSA 3072 lambat); PEM ditulis ulang ke tiap TempDir.
struct KeyPem {
  crypto::Algorithm alg;
  std::string priv_pem;
  std::string pub_pem;
  std::string keyid;
};

const KeyPem& key_for(crypto::Algorithm a) {
  static std::vector<KeyPem> cache;
  for (const auto& k : cache) {
    if (k.alg == a) return k;
  }
  auto kp = crypto::generate_keypair(a);
  REQUIRE(kp.has_value());
  auto priv = crypto::private_key_to_pem(kp->priv);
  auto pub = crypto::public_key_to_pem(kp->pub);
  REQUIRE(priv.has_value());
  REQUIRE(pub.has_value());
  cache.push_back(KeyPem{a, std::string(reinterpret_cast<const char*>(priv->data()), priv->size()),
                         *pub, *crypto::keyid(kp->pub)});
  return cache.back();
}

std::string sha256_hex_of(const std::string& data) {
  auto d = util::sha256(ByteView(reinterpret_cast<const std::uint8_t*>(data.data()), data.size()));
  REQUIRE(d.has_value());
  return util::hex_lower(*d);
}

struct AlgCase {
  crypto::Algorithm alg;
  const char* name;
};
const AlgCase kAlgs[] = {{crypto::Algorithm::Ed25519, "ed25519"},
                         {crypto::Algorithm::EcdsaP256, "ecdsa-p256-sha256"},
                         {crypto::Algorithm::RsaPss, "rsa-pss-sha256"}};

// Tanda tangan dan baca kembali bundle-nya; kembalikan manifest + bundle mentah.
struct Signed {
  bundle::Bundle bundle;
  manifest::Manifest manifest;
};

Signed sign_and_read(const TempDir& d, const KeyPem& k, const std::string& artifact_name,
                     const std::string& content, std::string_view package = "demo",
                     std::string_view version = "1.0.0") {
  spit(d.file("key.pem"), k.priv_pem);
  spit(d.file(artifact_name), content);
  auto r = run_cli({"sign", "-file", d.file(artifact_name), "-package", package, "-version",
                    version, "-key", d.file("key.pem"), "-out", d.file("out.bundle.json")});
  REQUIRE_MESSAGE(r.code == 0, r.err);
  auto b = bundle::read(slurp(d.file("out.bundle.json")));
  REQUIRE(b.has_value());
  std::string m_text(b->manifest.begin(), b->manifest.end());
  auto m = manifest::parse(m_text);
  REQUIRE(m.has_value());
  return Signed{*b, *m};
}

}  // namespace

TEST_CASE("sign: tiga algoritma, isi teks, biner, dan kosong") {
  std::string binary;
  for (int i = 0; i < 256; ++i) binary.push_back(static_cast<char>(i));
  const std::vector<std::pair<std::string, std::string>> contents = {
      {"note.txt", "halo dunia\n"}, {"blob.bin", binary}, {"empty.dat", ""}};

  for (const auto& a : kAlgs) {
    const KeyPem& k = key_for(a.alg);
    for (const auto& [name, content] : contents) {
      INFO(a.name << " " << name);
      TempDir d;
      auto s = sign_and_read(d, k, name, content);

      CHECK(s.manifest.package == "demo");
      CHECK(s.manifest.version == "1.0.0");
      CHECK(s.manifest.algorithm == a.name);
      CHECK(s.manifest.keyid == k.keyid);
      CHECK(s.manifest.artifact.name == name);
      CHECK(s.manifest.artifact.size == content.size());
      CHECK(s.manifest.artifact.sha256 == sha256_hex_of(content));
      CHECK(s.bundle.signature.size() == crypto::signature_size(a.alg));

      // Signature sah atas byte M persis seperti di bundle.
      auto pub = crypto::parse_public_key_pem(k.pub_pem);
      REQUIRE(pub.has_value());
      CHECK(crypto::verify(*pub, s.bundle.manifest, s.bundle.signature));
    }
  }
}

TEST_CASE("sign: berkas besar (banyak chunk) di-hash benar") {
  TempDir d;
  std::string big(64 * 1024 * 3 + 123, '\0');
  for (std::size_t i = 0; i < big.size(); ++i) big[i] = static_cast<char>(i * 31 + 7);
  auto s = sign_and_read(d, key_for(crypto::Algorithm::Ed25519), "big.bin", big);
  CHECK(s.manifest.artifact.size == big.size());
  CHECK(s.manifest.artifact.sha256 == sha256_hex_of(big));
}

TEST_CASE("sign: nama artefak = basename, bukan path") {
  TempDir d;
  fs::create_directory(d.path / "sub");
  auto s = sign_and_read(d, key_for(crypto::Algorithm::Ed25519), "sub/app.tar.gz", "x");
  CHECK(s.manifest.artifact.name == "app.tar.gz");
}

TEST_CASE("sign: Ed25519 deterministik, bundle identik untuk masukan sama") {
  TempDir d;
  const auto& k = key_for(crypto::Algorithm::Ed25519);
  sign_and_read(d, k, "a.txt", "isi");
  const std::string first = slurp(d.file("out.bundle.json"));
  sign_and_read(d, k, "a.txt", "isi");
  CHECK(slurp(d.file("out.bundle.json")) == first);
}

TEST_CASE("sign: ringkasan ke stdout tanpa materi kunci") {
  TempDir d;
  const auto& k = key_for(crypto::Algorithm::Ed25519);
  spit(d.file("key.pem"), k.priv_pem);
  spit(d.file("a.txt"), "isi");
  auto r = run_cli({"sign", "-file", d.file("a.txt"), "-package", "demo", "-version", "1", "-key",
                    d.file("key.pem"), "-out", d.file("o.json")});
  REQUIRE(r.code == 0);
  CHECK(r.out.find(k.keyid) != std::string::npos);
  CHECK(r.out.find("BEGIN") == std::string::npos);
  CHECK(r.err.empty());
}

TEST_CASE("sign: kegagalan input -> exit 2 dan tidak ada bundle") {
  TempDir d;
  const auto& k = key_for(crypto::Algorithm::Ed25519);
  spit(d.file("key.pem"), k.priv_pem);
  spit(d.file("a.txt"), "isi");
  const std::string out = d.file("o.json");

  auto sign = [&](std::string file, std::string pkg, std::string ver, std::string key) {
    return run_cli(
        {"sign", "-file", file, "-package", pkg, "-version", ver, "-key", key, "-out", out});
  };

  SUBCASE("berkas tidak ada") {
    CHECK(sign(d.file("none.txt"), "demo", "1", d.file("key.pem")).code == 2);
  }
  SUBCASE("artefak berupa direktori") {
    fs::create_directory(d.path / "dir");
    CHECK(sign(d.file("dir"), "demo", "1", d.file("key.pem")).code == 2);
  }
  SUBCASE("privkey tidak ada") {
    CHECK(sign(d.file("a.txt"), "demo", "1", d.file("none")).code == 2);
  }
  SUBCASE("privkey rusak") {
    spit(d.file("bad.pem"), "-----BEGIN PRIVATE KEY-----\nxx\n-----END PRIVATE KEY-----\n");
    auto r = sign(d.file("a.txt"), "demo", "1", d.file("bad.pem"));
    CHECK(r.code == 2);
    CHECK(r.err.find("xx") == std::string::npos);
  }
  SUBCASE("pubkey dipakai sebagai -key") {
    spit(d.file("pub.pem"), k.pub_pem);
    CHECK(sign(d.file("a.txt"), "demo", "1", d.file("pub.pem")).code == 2);
  }
  SUBCASE("package melanggar pola") {
    for (const char* bad : {"", "Demo", "a b", "-x", "*", "../x"}) {
      INFO(bad);
      CHECK(sign(d.file("a.txt"), bad, "1", d.file("key.pem")).code == 2);
    }
  }
  SUBCASE("version melanggar pola") {
    for (const char* bad : {"a b", "+1", "1/2", "v\"1"}) {
      INFO(bad);
      CHECK(sign(d.file("a.txt"), "demo", bad, d.file("key.pem")).code == 2);
    }
  }
  SUBCASE("nama berkas di luar pola") {
    spit(d.file("a b.txt"), "x");
    spit(d.file("caf\xC3\xA9.txt"), "x");
    CHECK(sign(d.file("a b.txt"), "demo", "1", d.file("key.pem")).code == 2);
    CHECK(sign(d.file("caf\xC3\xA9.txt"), "demo", "1", d.file("key.pem")).code == 2);
    // Spek: artifact.name harus diawali huruf/angka dan maksimum 128 karakter.
    spit(d.file(".hidden"), "x");
    spit(d.file("-dash.txt"), "x");
    spit(d.file(std::string(129, 'a')), "x");
    CHECK(sign(d.file(".hidden"), "demo", "1", d.file("key.pem")).code == 2);
    CHECK(sign(d.file("-dash.txt"), "demo", "1", d.file("key.pem")).code == 2);
    CHECK(sign(d.file(std::string(129, 'a')), "demo", "1", d.file("key.pem")).code == 2);
  }
  CHECK_FALSE(fs::exists(out));
}

TEST_CASE("sign: out tidak bisa ditulis -> exit 2") {
  TempDir d;
  const auto& k = key_for(crypto::Algorithm::Ed25519);
  spit(d.file("key.pem"), k.priv_pem);
  spit(d.file("a.txt"), "isi");
  auto r = run_cli({"sign", "-file", d.file("a.txt"), "-package", "demo", "-version", "1", "-key",
                    d.file("key.pem"), "-out", d.file("tidak-ada/o.json")});
  CHECK(r.code == 2);
  CHECK(r.err.find("tidak bisa menulis bundle") != std::string::npos);
  CHECK(r.out.empty());
}

TEST_CASE("sign: bundle yang ada ditimpa dengan hasil baru") {
  TempDir d;
  const auto& k = key_for(crypto::Algorithm::Ed25519);
  sign_and_read(d, k, "a.txt", "satu");
  auto second = sign_and_read(d, k, "a.txt", "dua");
  CHECK(second.manifest.artifact.sha256 == sha256_hex_of("dua"));
}

TEST_CASE("sign: flag wajib dan -help") {
  auto r = run_cli({"sign", "-file", "a"});
  CHECK(r.code == 2);
  CHECK(r.err.find("flag wajib hilang") != std::string::npos);
  auto h = run_cli({"sign", "-help"});
  CHECK(h.code == 0);
  CHECK(h.out.find("usage: sister-sign sign") != std::string::npos);
}
