// T37 (bonus): `sbom sign | verify | check`.
#include <doctest/doctest.h>
#include <unistd.h>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "cli/cli.hpp"
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
    std::string tmpl = (fs::temp_directory_path() / "cli_sbom_XXXXXX").string();
    REQUIRE(::mkdtemp(tmpl.data()) != nullptr);
    path = tmpl;
  }
  ~TempDir() {
    std::error_code ec;
    fs::remove_all(path, ec);
  }
  std::string operator/(std::string_view name) const { return (path / name).string(); }
};

void write(const std::string& path, std::string_view data) {
  std::ofstream f(path, std::ios::binary | std::ios::trunc);
  f.write(data.data(), static_cast<std::streamsize>(data.size()));
  REQUIRE(f.good());
}

std::string sha_hex(std::string_view s) {
  auto d = util::sha256(ByteView(reinterpret_cast<const std::uint8_t*>(s.data()), s.size()));
  REQUIRE(d.has_value());
  return util::hex_lower(*d);
}

std::string cyclonedx(std::string_view name, std::string_view version, std::string_view hashes) {
  return std::string(R"({"bomFormat":"CycloneDX","specVersion":"1.6","version":1,)") +
         R"("metadata":{"timestamp":"2026-11-15T00:00:00Z","component":{"type":"application",)" +
         R"("name":")" + std::string(name) + R"(","version":")" + std::string(version) +
         R"(","hashes":[)" + std::string(hashes) + R"(]}},)" +
         R"("components":[{"type":"library","name":"openssl","version":"3.5.7"}]})";
}

std::string sha_entry(std::string_view hex) {
  return R"({"alg":"SHA-256","content":")" + std::string(hex) + R"("})";
}

// Kunci Ed25519 + trust store untuk package "app", artefak, dan SBOM yang menyebut hash artefak.
struct Fixture {
  TempDir dir;
  std::string artifact_content = "isi artefak rilis\n";
  Fixture() {
    REQUIRE(run_cli({"keygen", "-algorithm", "ed25519", "-out", dir / "k"}).code == 0);
    REQUIRE(run_cli({"trust", "add", "-store", dir / "t.json", "-key", dir / "k.pub.pem",
                     "-package", "app"})
                .code == 0);
    write(dir / "app.bin", artifact_content);
    write(dir / "app.cdx.json", cyclonedx("app", "1.0.0", sha_entry(sha_hex(artifact_content))));
  }
  Run sign() {
    return run_cli({"sbom", "sign", "-sbom", dir / "app.cdx.json", "-package", "app", "-version",
                    "1.0.0", "-key", dir / "k.key.pem", "-out", dir / "sbom.bundle.json"});
  }
  Run verify(std::string_view version = "1.0.0") {
    return run_cli({"sbom", "verify", "-sbom", dir / "app.cdx.json", "-bundle",
                    dir / "sbom.bundle.json", "-trust-store", dir / "t.json", "-package", "app",
                    "-version", version, "-json"});
  }
  Run check() {
    return run_cli(
        {"sbom", "check", "-sbom", dir / "app.cdx.json", "-file", dir / "app.bin", "-json"});
  }
};

bool has_status(const Run& r, std::string_view status) {
  return r.out.find(std::string(R"("status":")") + std::string(status) + "\"") != std::string::npos;
}

}  // namespace

TEST_CASE("sbom: sign -> verify -> check OK, bundle sama formatnya dengan sign") {
  Fixture f;
  auto s = f.sign();
  REQUIRE(s.code == 0);
  CHECK(s.out.find("sbom artifact sha256: " + sha_hex(f.artifact_content)) != std::string::npos);
  std::ifstream b(f.dir / "sbom.bundle.json");
  std::string bundle((std::istreambuf_iterator<char>(b)), std::istreambuf_iterator<char>());
  CHECK(bundle.starts_with(R"({"schema":"minisign-bundle/v1","manifest_b64":")"));

  auto v = f.verify();
  CHECK(v.code == 0);
  CHECK(has_status(v, "OK"));
  // Bundle SBOM juga lolos `verify` biasa (format yang sama).
  CHECK(run_cli({"verify", "-file", f.dir / "app.cdx.json", "-bundle", f.dir / "sbom.bundle.json",
                 "-trust-store", f.dir / "t.json", "-package", "app", "-version", "1.0.0"})
            .code == 0);
  auto c = f.check();
  CHECK(c.code == 0);
  CHECK(has_status(c, "OK"));
  CHECK(c.out.find(R"("package":"app","version":"1.0.0")") != std::string::npos);
}

TEST_CASE("sbom: isi SBOM diubah setelah sign -> verify ditolak") {
  Fixture f;
  REQUIRE(f.sign().code == 0);
  // Ganti nama library (ukuran sama) -> SHA-256 berkas SBOM berubah.
  std::ifstream in(f.dir / "app.cdx.json");
  std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  in.close();
  const auto pos = text.find("openssl");
  REQUIRE(pos != std::string::npos);
  text.replace(pos, 7, "libressl");
  write(f.dir / "app.cdx.json", text);
  auto v = f.verify();
  CHECK(v.code == 1);
  CHECK(has_status(v, "ARTIFACT_MISMATCH"));
}

TEST_CASE("sbom: artefak rilis diganti -> check (keterikatan) gagal") {
  Fixture f;
  REQUIRE(f.sign().code == 0);
  REQUIRE(f.verify().code == 0);
  write(f.dir / "app.bin", "artefak lain\n");
  auto c = f.check();
  CHECK(c.code == 1);
  CHECK(has_status(c, "ARTIFACT_MISMATCH"));
}

TEST_CASE("sbom: SBOM tanpa hash artefak -> sign ditolak (exit 2), check FORMAT_ERROR") {
  Fixture f;
  write(f.dir / "app.cdx.json", cyclonedx("app", "1.0.0", R"({"alg":"SHA-1","content":"00"})"));
  auto s = f.sign();
  CHECK(s.code == 2);
  CHECK(s.err.find("SHA-256") != std::string::npos);
  CHECK_FALSE(fs::exists(f.dir / "sbom.bundle.json"));
  auto c = f.check();
  CHECK(c.code == 1);
  CHECK(has_status(c, "FORMAT_ERROR"));
}

TEST_CASE("sbom: isi tidak sah atau ambigu -> ditolak") {
  Fixture f;
  SUBCASE("dua SHA-256 berbeda") {
    write(f.dir / "app.cdx.json",
          cyclonedx("app", "1.0.0",
                    sha_entry(sha_hex("a")) + "," + sha_entry(sha_hex(f.artifact_content))));
  }
  SUBCASE("key ganda") {
    write(f.dir / "app.cdx.json",
          R"({"bomFormat":"CycloneDX","bomFormat":"CycloneDX","specVersion":"1.6","metadata":{}})");
  }
  SUBCASE("bukan CycloneDX") { write(f.dir / "app.cdx.json", R"({"spdxVersion":"SPDX-2.3"})"); }
  SUBCASE("hash bukan 64 hex") {
    write(f.dir / "app.cdx.json", cyclonedx("app", "1.0.0", sha_entry("abc")));
  }
  CHECK(f.sign().code == 2);
  auto c = f.check();
  CHECK(c.code == 1);
  CHECK(has_status(c, "FORMAT_ERROR"));
}

TEST_CASE("sbom: SBOM untuk package/versi lain") {
  Fixture f;
  write(f.dir / "app.cdx.json",
        cyclonedx("other", "1.0.0", sha_entry(sha_hex(f.artifact_content))));
  CHECK(f.sign().code == 2);  // component.name != -package

  write(f.dir / "app.cdx.json", cyclonedx("app", "1.0.0", sha_entry(sha_hex(f.artifact_content))));
  REQUIRE(f.sign().code == 0);
  auto v = f.verify("2.0.0");
  CHECK(v.code == 1);
  CHECK(has_status(v, "METADATA_MISMATCH"));
}

TEST_CASE("sbom: kunci tidak dipercaya -> KEY_NOT_TRUSTED") {
  Fixture f;
  REQUIRE(f.sign().code == 0);
  write(f.dir / "t.json", R"({"schema":"minisign-trust/v1","keys":[]})");
  auto v = f.verify();
  CHECK(v.code == 1);
  CHECK(has_status(v, "KEY_NOT_TRUSTED"));
}

TEST_CASE("sbom: pemakaian salah -> exit 2") {
  CHECK(run_cli({"sbom"}).code == 2);
  CHECK(run_cli({"sbom", "bogus"}).code == 2);
  CHECK(run_cli({"sbom", "-help"}).code == 0);
  CHECK(run_cli({"sbom", "check", "-sbom", "x.json"}).code == 2);  // -file hilang
  auto r = run_cli({"sbom", "check", "-json"});
  CHECK(r.code == 2);
  CHECK(has_status(r, "INPUT_ERROR"));
  auto missing = run_cli({"sbom", "check", "-sbom", "/nonexistent.json", "-file", "/x", "-json"});
  CHECK(missing.code == 2);
  CHECK(has_status(missing, "INPUT_ERROR"));
}
