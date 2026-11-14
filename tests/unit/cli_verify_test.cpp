#include <doctest/doctest.h>
#include <unistd.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <functional>
#include <glaze/glaze.hpp>
#include <iterator>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include "bundle/bundle.hpp"
#include "cli/cli.hpp"
#include "crypto/keyio.hpp"
#include "manifest/manifest.hpp"
#include "util/hash.hpp"
#include "util/hex.hpp"
#include "util/json_scan.hpp"

using namespace sister_sign;
using namespace sister_sign::cli;
namespace fs = std::filesystem;

namespace {

struct JsonResult {
  bool valid = false;
  std::string status;
  std::string message;
  std::optional<std::string> algorithm;
  std::optional<std::string> keyid;
  std::optional<std::string> package;
  std::optional<std::string> version;
};

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
    std::string tmpl = (fs::temp_directory_path() / "cli_verify_XXXXXX").string();
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

void spit(const fs::path& p, const std::string& data) {
  std::ofstream(p, std::ios::binary) << data;
}

// Lingkungan lengkap lewat CLI: keygen -> trust add -> sign. Hanya perintah yang diuji di tempat
// lain yang dipakai di sini.
struct Env {
  TempDir d;
  std::string prefix = d.file("k");
  std::string artifact = d.file("app.bin");
  std::string bundle = d.file("app.bundle.json");
  std::string store = d.file("trust.json");

  explicit Env(const char* algorithm = "ed25519") {
    spit(artifact, "isi artefak\n");
    REQUIRE(run_cli({"keygen", "-algorithm", algorithm, "-out", prefix}).code == 0);
    REQUIRE(
        run_cli({"trust", "add", "-store", store, "-key", prefix + ".pub.pem", "-package", "demo"})
            .code == 0);
    REQUIRE(run_cli({"sign", "-file", artifact, "-package", "demo", "-version", "1.0.0", "-key",
                     prefix + ".key.pem", "-out", bundle})
                .code == 0);
  }

  Run verify(bool json = false, std::string_view package = "demo",
             std::string_view version = "1.0.0") const {
    std::vector<std::string_view> args = {"verify", "-file",        artifact, "-bundle",
                                          bundle,   "-trust-store", store,    "-package",
                                          package,  "-version",     version};
    if (json) args.push_back("-json");
    return run_cli(args);
  }
};

JsonResult parse_json(const std::string& out) {
  // Tepat satu baris: objek + newline.
  REQUIRE(!out.empty());
  CHECK(out.back() == '\n');
  CHECK(std::count(out.begin(), out.end(), '\n') == 1);
  const std::string body = out.substr(0, out.size() - 1);
  REQUIRE(util::check_json_no_duplicate_keys(body).has_value());
  JsonResult r;
  constexpr glz::opts kOpts{.error_on_unknown_keys = true, .error_on_missing_keys = true};
  REQUIRE_FALSE(glz::read<kOpts>(r, body));
  return r;
}

// Semua status gagal: kode keluar dan nama status.
void expect_fail(const Run& r, int code, const char* status) {
  INFO(r.err);
  CHECK(r.code == code);
  CHECK(r.err.rfind(std::string(status) + ":", 0) == 0);
  CHECK(r.out.empty());
}

void no_key_material(const Run& r) {
  CHECK(r.out.find("BEGIN") == std::string::npos);
  CHECK(r.err.find("BEGIN") == std::string::npos);
}

}  // namespace

TEST_CASE("verify cli: OK untuk tiga algoritma, exit 0") {
  for (const char* alg : {"ed25519", "ecdsa-p256-sha256", "rsa-pss-sha256"}) {
    INFO(alg);
    Env e(alg);
    auto r = e.verify();
    CHECK(r.code == 0);
    CHECK(r.err.empty());
    CHECK(r.out.rfind("OK:", 0) == 0);
    CHECK(r.out.find('{') == std::string::npos);
    no_key_material(r);
  }
}

TEST_CASE("verify cli: -json OK -> satu objek JSON, exit 0") {
  Env e;
  auto r = e.verify(true);
  CHECK(r.code == 0);
  CHECK(r.err.empty());
  auto j = parse_json(r.out);
  CHECK(j.valid);
  CHECK(j.status == "OK");
  CHECK(j.algorithm == "ed25519");
  CHECK(j.package == "demo");
  CHECK(j.version == "1.0.0");
  REQUIRE(j.keyid.has_value());
  CHECK(j.keyid->size() == 64);
}

TEST_CASE("verify cli: urutan field JSON tetap") {
  Env e;
  const auto out = e.verify(true).out;
  const auto pos = [&](const char* k) { return out.find(std::string("\"") + k + "\":"); };
  CHECK(pos("valid") < pos("status"));
  CHECK(pos("status") < pos("message"));
  CHECK(pos("message") < pos("algorithm"));
  CHECK(pos("algorithm") < pos("keyid"));
  CHECK(pos("keyid") < pos("package"));
  CHECK(pos("package") < pos("version"));
}

TEST_CASE("verify cli: tiap status gagal -> exit code, stderr, dan JSON yang benar") {
  struct Case {
    const char* name;
    const char* status;
    int code;
    std::function<void(Env&)> mutate;
    std::string_view package = "demo";
    std::string_view version = "1.0.0";
  };
  std::vector<Case> cases;
  cases.push_back({"INPUT_ERROR", "INPUT_ERROR", 2, [](Env& e) { fs::remove(e.artifact); }});
  cases.push_back(
      {"FORMAT_ERROR", "FORMAT_ERROR", 1, [](Env& e) { spit(e.bundle, "bukan json"); }});
  cases.push_back({"KEY_NOT_TRUSTED", "KEY_NOT_TRUSTED", 1, [](Env& e) {
                     REQUIRE(run_cli({"trust", "remove", "-store", e.store, "-keyid",
                                      [&] {
                                        auto s = slurp(e.store);
                                        auto p = s.find("\"keyid\": \"") + 10;
                                        return s.substr(p, 64);
                                      }()})
                                 .code == 0);
                   }});
  cases.push_back({"INVALID_SIGNATURE", "INVALID_SIGNATURE", 1, [](Env& e) {
                     auto b = bundle::read(slurp(e.bundle));
                     REQUIRE(b.has_value());
                     b->signature[0] ^= 1;
                     spit(e.bundle, *bundle::write(*b));
                   }});
  cases.push_back({"METADATA_MISMATCH", "METADATA_MISMATCH", 1, [](Env&) {}, "demo", "9.9.9"});
  cases.push_back({"ARTIFACT_MISMATCH", "ARTIFACT_MISMATCH", 1,
                   [](Env& e) { spit(e.artifact, "isi artefak berubah\n"); }});

  for (auto& c : cases) {
    INFO(c.name);
    {
      Env e;
      c.mutate(e);
      auto r = e.verify(false, c.package, c.version);
      expect_fail(r, c.code, c.status);
      CHECK(r.out.find('{') == std::string::npos);
      no_key_material(r);
    }
    {
      Env e;
      c.mutate(e);
      auto r = e.verify(true, c.package, c.version);
      CHECK(r.code == c.code);
      CHECK(r.err.rfind(std::string(c.status) + ":", 0) == 0);
      auto j = parse_json(r.out);
      CHECK_FALSE(j.valid);
      CHECK(j.status == c.status);
      CHECK_FALSE(j.message.empty());
      no_key_material(r);
    }
  }
}

TEST_CASE("verify cli: UNSUPPORTED_ALGORITHM (manifest ditandatangani sah)") {
  Env e;
  auto kp = crypto::read_private_key(e.prefix + ".key.pem");
  REQUIRE(kp.has_value());
  auto pub = crypto::read_public_key(e.prefix + ".pub.pem");
  manifest::Manifest m;
  m.package = "demo";
  m.version = "1.0.0";
  m.algorithm = "ed448";
  m.keyid = *crypto::keyid(*pub);
  m.artifact = manifest::ArtifactInfo{"app.bin", 12, std::string(64, 'a')};
  const std::string text = *manifest::serialize(m);
  const Bytes mb(text.begin(), text.end());
  spit(e.bundle, *bundle::write(bundle::Bundle{mb, *crypto::sign(*kp, mb)}));

  expect_fail(e.verify(), 1, "UNSUPPORTED_ALGORITHM");
  auto j = e.verify(true);
  CHECK(j.code == 1);
  CHECK(parse_json(j.out).status == "UNSUPPORTED_ALGORITHM");
}

TEST_CASE("verify cli: field JSON null selama manifest belum terbaca, terisi sesudahnya") {
  SUBCASE("FORMAT_ERROR -> semua null") {
    Env e;
    spit(e.bundle, "bukan json");
    auto r = e.verify(true);
    CHECK(r.code == 1);
    auto j = parse_json(r.out);
    CHECK(j.status == "FORMAT_ERROR");
    CHECK_FALSE(j.algorithm.has_value());
    CHECK_FALSE(j.keyid.has_value());
    CHECK_FALSE(j.package.has_value());
    CHECK_FALSE(j.version.has_value());
    CHECK(r.out.find(R"("keyid":null)") != std::string::npos);
  }
  SUBCASE("INPUT_ERROR -> semua null") {
    Env e;
    fs::remove(e.artifact);
    auto j = parse_json(e.verify(true).out);
    CHECK(j.status == "INPUT_ERROR");
    CHECK_FALSE(j.keyid.has_value());
  }
  SUBCASE("KEY_NOT_TRUSTED -> terisi dari manifest") {
    Env e;
    spit(e.store, R"({"schema":"minisign-trust/v1","keys":[]})");
    auto j = parse_json(e.verify(true).out);
    CHECK(j.status == "KEY_NOT_TRUSTED");
    CHECK(j.algorithm == "ed25519");
    CHECK(j.package == "demo");
    CHECK(j.version == "1.0.0");
    REQUIRE(j.keyid.has_value());
    CHECK(j.keyid->size() == 64);
  }
}

TEST_CASE("verify cli: package yang diminta pengguna tidak diizinkan -> KEY_NOT_TRUSTED") {
  Env e;
  auto r = e.verify(true, "lain", "1.0.0");
  CHECK(r.code == 1);
  CHECK(parse_json(r.out).status == "KEY_NOT_TRUSTED");
}

TEST_CASE("verify cli: METADATA_MISMATCH dengan JSON memuat field terotentikasi") {
  Env e;
  auto j = parse_json(e.verify(true, "demo", "2.0.0").out);
  CHECK(j.status == "METADATA_MISMATCH");
  CHECK(j.package == "demo");
  CHECK(j.version == "1.0.0");  // dari manifest, bukan masukan pengguna
}

TEST_CASE("verify cli: JSON tetap valid untuk karakter khusus dan UTF-8 tidak sah") {
  Env e;
  for (const std::string& weird :
       {std::string("a\"b\\c"), std::string("tab\there"), std::string("baris\nbaru"),
        std::string("\xff\xfe"), std::string("caf\xC3\xA9"), std::string("\xED\xA0\x80")}) {
    INFO(weird);
    auto r = e.verify(true, "demo", weird);
    CHECK(r.code == 1);
    auto j = parse_json(r.out);
    CHECK(j.status == "METADATA_MISMATCH");
    CHECK_FALSE(j.message.empty());
  }
  // Karakter kontrol/quote muncul apa adanya setelah di-decode.
  auto j = parse_json(e.verify(true, "demo", "a\"b\\c").out);
  CHECK(j.message.find("a\"b\\c") != std::string::npos);
}

TEST_CASE("verify cli: stdin ditutup tidak menggantung (tidak membaca stdin)") {
  // run() tidak pernah menyentuh stdin; ctest cli_no_stdin membuktikan di level proses.
  Env e;
  CHECK(e.verify().code == 0);
}

TEST_CASE("verify cli: kesalahan pemakaian -> exit 2; dengan -json tetap satu objek JSON") {
  auto r = run_cli({"verify", "-file", "a", "-json"});
  CHECK(r.code == 2);
  CHECK(r.err.find("flag wajib hilang") != std::string::npos);
  auto j = parse_json(r.out);
  CHECK_FALSE(j.valid);
  CHECK(j.status == "INPUT_ERROR");
  CHECK_FALSE(j.keyid.has_value());

  auto unknown = run_cli({"verify", "-bogus", "x", "--json"});
  CHECK(unknown.code == 2);
  CHECK(parse_json(unknown.out).status == "INPUT_ERROR");

  // Tanpa -json: stdout kosong.
  auto plain = run_cli({"verify", "-file", "a"});
  CHECK(plain.code == 2);
  CHECK(plain.out.empty());
  CHECK(run_cli({"verify", "-help"}).code == 0);
}

TEST_CASE("verify cli: input tidak berubah setelah verify") {
  Env e;
  const auto b = slurp(e.bundle);
  const auto t = slurp(e.store);
  const auto f = slurp(e.artifact);
  e.verify();
  e.verify(true);
  CHECK(slurp(e.bundle) == b);
  CHECK(slurp(e.store) == t);
  CHECK(slurp(e.artifact) == f);
}
