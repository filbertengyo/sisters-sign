#include <doctest/doctest.h>
#include <unistd.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

#include "cli/cli.hpp"
#include "crypto/keyio.hpp"
#include "trust/trust.hpp"

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
    std::string tmpl = (fs::temp_directory_path() / "cli_trust_XXXXXX").string();
    REQUIRE(::mkdtemp(tmpl.data()) != nullptr);
    path = tmpl;
  }
  ~TempDir() {
    std::error_code ec;
    fs::remove_all(path, ec);
  }
  std::string file(const std::string& name) const { return (path / name).string(); }
};

std::string slurp(const fs::path& p) {
  std::ifstream f(p, std::ios::binary);
  return std::string(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
}

struct Generated {
  std::string pub_path;
  std::string keyid;
};

// Buat pubkey lewat library (tanpa privkey di disk).
Generated make_pub(const TempDir& d, const std::string& name, crypto::Algorithm a) {
  auto kp = crypto::generate_keypair(a);
  REQUIRE(kp.has_value());
  Generated g{d.file(name + ".pub.pem"), *crypto::keyid(kp->pub)};
  REQUIRE(crypto::write_public_key(g.pub_path, kp->pub).has_value());
  return g;
}

}  // namespace

TEST_CASE("trust cli: add -> list -> remove -> list untuk tiga algoritma") {
  TempDir d;
  const std::string store = d.file("trust.json");
  struct C {
    const char* name;
    crypto::Algorithm alg;
    const char* label;
  };
  for (const C& c : {C{"ed", crypto::Algorithm::Ed25519, "ed25519"},
                     C{"ec", crypto::Algorithm::EcdsaP256, "ecdsa-p256-sha256"},
                     C{"rsa", crypto::Algorithm::RsaPss, "rsa-pss-sha256"}}) {
    INFO(c.label);
    auto g = make_pub(d, c.name, c.alg);

    auto add = run_cli({"trust", "add", "-store", store, "-key", g.pub_path, "-package", "demo"});
    REQUIRE(add.code == 0);
    CHECK(add.out.find(g.keyid) != std::string::npos);
    CHECK(add.out.find(c.label) != std::string::npos);

    auto list = run_cli({"trust", "list", "-store", store});
    REQUIRE(list.code == 0);
    CHECK(list.out.find(g.keyid) != std::string::npos);
    CHECK(list.out.find(c.label) != std::string::npos);
    CHECK(list.out.find("demo") != std::string::npos);

    auto rm = run_cli({"trust", "remove", "-store", store, "-keyid", g.keyid});
    REQUIRE(rm.code == 0);
    CHECK(rm.out.find(g.keyid) != std::string::npos);

    auto after = run_cli({"trust", "list", "-store", store});
    REQUIRE(after.code == 0);
    CHECK(after.out.find(g.keyid) == std::string::npos);
  }
}

TEST_CASE("trust cli: store dapat dipakai library setelah add") {
  TempDir d;
  const std::string store = d.file("trust.json");
  auto g = make_pub(d, "k", crypto::Algorithm::Ed25519);
  REQUIRE(run_cli({"trust", "add", "-store", store, "-key", g.pub_path, "-package", "demo"}).code ==
          0);
  auto s = trust::TrustStore::load(store);
  REQUIRE(s.has_value());
  CHECK(s->lookup(g.keyid, "demo", crypto::Algorithm::Ed25519).has_value());
  CHECK_FALSE(s->lookup(g.keyid, "lain", crypto::Algorithm::Ed25519).has_value());
}

TEST_CASE("trust cli: add dua kali idempoten (berkas identik)") {
  TempDir d;
  const std::string store = d.file("trust.json");
  auto g = make_pub(d, "k", crypto::Algorithm::Ed25519);
  std::vector<std::string_view> add = {"trust", "add",      "-store",   store,
                                       "-key",  g.pub_path, "-package", "demo"};
  REQUIRE(run_cli(add).code == 0);
  const std::string once = slurp(store);
  REQUIRE(run_cli(add).code == 0);
  CHECK(slurp(store) == once);
}

TEST_CASE("trust cli: add package kedua menambah package pada entri yang sama") {
  TempDir d;
  const std::string store = d.file("trust.json");
  auto g = make_pub(d, "k", crypto::Algorithm::Ed25519);
  REQUIRE(
      run_cli({"trust", "add", "-store", store, "-key", g.pub_path, "-package", "alpha"}).code ==
      0);
  REQUIRE(run_cli({"trust", "add", "-store", store, "-key", g.pub_path, "-package", "beta"}).code ==
          0);
  auto s = trust::TrustStore::load(store);
  REQUIRE(s.has_value());
  REQUIRE(s->entries().size() == 1);
  CHECK(s->entries()[0].packages == std::vector<std::string>{"alpha", "beta"});
  auto list = run_cli({"trust", "list", "-store", store});
  CHECK(list.out.find("alpha,beta") != std::string::npos);
}

TEST_CASE("trust cli: remove keyid asing -> exit 2, store tidak berubah") {
  TempDir d;
  const std::string store = d.file("trust.json");
  auto g = make_pub(d, "k", crypto::Algorithm::Ed25519);
  REQUIRE(run_cli({"trust", "add", "-store", store, "-key", g.pub_path, "-package", "demo"}).code ==
          0);
  const std::string before = slurp(store);
  auto r = run_cli({"trust", "remove", "-store", store, "-keyid", std::string(64, '0')});
  CHECK(r.code == 2);
  CHECK(r.err.find("tidak ada") != std::string::npos);
  CHECK(slurp(store) == before);
}

TEST_CASE("trust cli: add dengan pubkey rusak -> exit 2, store tidak dibuat") {
  TempDir d;
  const std::string store = d.file("trust.json");
  const std::string bad = d.file("bad.pub.pem");
  std::ofstream(bad) << "-----BEGIN PUBLIC KEY-----\nbukan-kunci\n-----END PUBLIC KEY-----\n";
  auto r = run_cli({"trust", "add", "-store", store, "-key", bad, "-package", "demo"});
  CHECK(r.code == 2);
  CHECK_FALSE(fs::exists(store));

  auto missing = run_cli(
      {"trust", "add", "-store", store, "-key", d.file("tidak-ada.pem"), "-package", "demo"});
  CHECK(missing.code == 2);
  CHECK_FALSE(fs::exists(store));
}

TEST_CASE("trust cli: add menolak privkey sebagai -key") {
  TempDir d;
  auto kp = crypto::generate_keypair(crypto::Algorithm::Ed25519);
  REQUIRE(kp.has_value());
  const std::string priv = d.file("k.key.pem");
  REQUIRE(crypto::write_private_key(priv, kp->priv).has_value());
  auto r = run_cli({"trust", "add", "-store", d.file("t.json"), "-key", priv, "-package", "demo"});
  CHECK(r.code == 2);
  // Pesan boleh menyebut label, tetapi tidak pernah isi kunci.
  const std::string pem = slurp(priv);
  const auto body_start = pem.find('\n') + 1;
  CHECK(r.err.find(pem.substr(body_start, 20)) == std::string::npos);
  CHECK(r.out.empty());
}

TEST_CASE("trust cli: package di luar pola -> exit 2") {
  TempDir d;
  const std::string store = d.file("trust.json");
  auto g = make_pub(d, "k", crypto::Algorithm::Ed25519);
  for (const char* bad : {"*", "Demo", "a b"}) {
    INFO(bad);
    auto r = run_cli({"trust", "add", "-store", store, "-key", g.pub_path, "-package", bad});
    CHECK(r.code == 2);
  }
  CHECK_FALSE(fs::exists(store));
}

TEST_CASE("trust cli: store rusak tidak ditimpa") {
  TempDir d;
  const std::string store = d.file("trust.json");
  std::ofstream(store) << "{bukan json";
  auto g = make_pub(d, "k", crypto::Algorithm::Ed25519);

  CHECK(run_cli({"trust", "add", "-store", store, "-key", g.pub_path, "-package", "demo"}).code ==
        2);
  CHECK(run_cli({"trust", "list", "-store", store}).code == 2);
  CHECK(run_cli({"trust", "remove", "-store", store, "-keyid", g.keyid}).code == 2);
  CHECK(slurp(store) == "{bukan json");
}

TEST_CASE("trust cli: list dan remove pada store yang tidak ada -> exit 2") {
  TempDir d;
  CHECK(run_cli({"trust", "list", "-store", d.file("none.json")}).code == 2);
  CHECK(run_cli({"trust", "remove", "-store", d.file("none.json"), "-keyid", std::string(64, 'a')})
            .code == 2);
  CHECK_FALSE(fs::exists(d.file("none.json")));
}

TEST_CASE("trust cli: list store kosong hanya mencetak header") {
  TempDir d;
  const std::string store = d.file("trust.json");
  REQUIRE(trust::TrustStore{}.save(store).has_value());
  auto r = run_cli({"trust", "list", "-store", store});
  CHECK(r.code == 0);
  CHECK(r.out.rfind("KEYID", 0) == 0);
  CHECK(std::count(r.out.begin(), r.out.end(), '\n') == 1);
}

TEST_CASE("trust cli: flag wajib dan -help per aksi") {
  CHECK(run_cli({"trust", "add"}).code == 2);
  CHECK(run_cli({"trust", "add"}).err.find("flag wajib hilang: -store") != std::string::npos);
  CHECK(run_cli({"trust", "add", "-store", "t"}).err.find("-key") != std::string::npos);
  CHECK(run_cli({"trust", "list"}).code == 2);
  CHECK(run_cli({"trust", "remove", "-store", "t"}).err.find("-keyid") != std::string::npos);
  CHECK(run_cli({"trust", "list", "-bogus", "1"}).code == 2);
  for (auto a : {"add", "list", "remove"}) {
    auto r = run_cli({"trust", a, "-help"});
    CHECK(r.code == 0);
    CHECK(r.out.find(std::string("usage: sister-sign trust ") + a) != std::string::npos);
  }
}
