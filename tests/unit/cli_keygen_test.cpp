#include <doctest/doctest.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

#include "cli/cli.hpp"
#include "crypto/keyio.hpp"

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
    std::string tmpl = (fs::temp_directory_path() / "keygen_test_XXXXXX").string();
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

// Ambil nilai setelah "<label>: " pada baris keluaran.
std::string field(const std::string& out, const std::string& label) {
  auto pos = out.find(label + ": ");
  REQUIRE(pos != std::string::npos);
  pos += label.size() + 2;
  return out.substr(pos, out.find('\n', pos) - pos);
}

unsigned mode_of(const fs::path& p) {
  struct stat st;
  REQUIRE(::stat(p.c_str(), &st) == 0);
  return st.st_mode & 0777;
}

std::size_t count_files(const fs::path& dir) {
  std::size_t n = 0;
  for (auto it = fs::directory_iterator(dir); it != fs::directory_iterator(); ++it) ++n;
  return n;
}

struct AlgCase {
  const char* flag;
  crypto::Algorithm alg;
  const char* name;
};

const AlgCase kCases[] = {
    {"ed25519", crypto::Algorithm::Ed25519, "ed25519"},
    {"ecdsa", crypto::Algorithm::EcdsaP256, "ecdsa-p256"},
    {"ecdsa-p256", crypto::Algorithm::EcdsaP256, "ecdsa-p256"},
    {"rsa-pss", crypto::Algorithm::RsaPss, "rsa-pss"},
};

}  // namespace

TEST_CASE("keygen: tiga algoritma menghasilkan pasangan kunci yang valid") {
  for (const auto& c : kCases) {
    INFO(c.flag);
    TempDir d;
    const std::string prefix = (d.path / "k").string();
    auto r = run_cli({"keygen", "-algorithm", c.flag, "-out", prefix});
    REQUIRE(r.code == 0);
    CHECK(r.err.empty());

    const fs::path key_path = prefix + ".key.pem";
    const fs::path pub_path = prefix + ".pub.pem";
    REQUIRE(fs::exists(key_path));
    REQUIRE(fs::exists(pub_path));
    CHECK(count_files(d.path) == 2);

    auto priv = crypto::read_private_key(key_path);
    auto pub = crypto::read_public_key(pub_path);
    REQUIRE(priv.has_value());
    REQUIRE(pub.has_value());
    CHECK(priv->algorithm() == c.alg);
    CHECK(pub->algorithm() == c.alg);

    // Pubkey memang pasangan privkey, dan keyid yang dicetak = keyid dari kunci.
    auto derived = crypto::public_key_of(*priv);
    REQUIRE(derived.has_value());
    auto id_pub = crypto::keyid(*pub);
    auto id_derived = crypto::keyid(*derived);
    REQUIRE(id_pub.has_value());
    REQUIRE(id_derived.has_value());
    CHECK(*id_pub == *id_derived);
    CHECK(field(r.out, "keyid") == *id_pub);
    CHECK(field(r.out, "algorithm") == c.name);
    CHECK(field(r.out, "private key") == key_path.string());
    CHECK(field(r.out, "public key") == pub_path.string());

    // Tanda tangan dari privkey lolos dengan pubkey yang ditulis.
    const Bytes msg{'h', 'i'};
    auto sig = crypto::sign(*priv, msg);
    REQUIRE(sig.has_value());
    CHECK(crypto::verify(*pub, msg, *sig));
  }
}

TEST_CASE("keygen: permission privkey 0600, pubkey 0644") {
  TempDir d;
  const std::string prefix = (d.path / "k").string();
  REQUIRE(run_cli({"keygen", "-algorithm", "ed25519", "-out", prefix}).code == 0);
  CHECK(mode_of(prefix + ".key.pem") == 0600);
  CHECK(mode_of(prefix + ".pub.pem") == 0644);
}

TEST_CASE("keygen: isi privkey tidak pernah dicetak") {
  TempDir d;
  const std::string prefix = (d.path / "k").string();
  auto r = run_cli({"keygen", "-algorithm", "ed25519", "-out", prefix});
  REQUIRE(r.code == 0);
  CHECK(r.out.find("BEGIN") == std::string::npos);
  CHECK(r.err.find("BEGIN") == std::string::npos);
}

TEST_CASE("keygen: berkas sudah ada tanpa -force -> exit 2, isi tidak berubah") {
  TempDir d;
  const std::string prefix = (d.path / "k").string();
  REQUIRE(run_cli({"keygen", "-algorithm", "ed25519", "-out", prefix}).code == 0);
  const std::string key_before = slurp(prefix + ".key.pem");
  const std::string pub_before = slurp(prefix + ".pub.pem");

  auto r = run_cli({"keygen", "-algorithm", "ed25519", "-out", prefix});
  CHECK(r.code == 2);
  CHECK(r.err.find("sudah ada") != std::string::npos);
  CHECK(r.err.find("-force") != std::string::npos);
  CHECK(r.out.empty());
  CHECK(slurp(prefix + ".key.pem") == key_before);
  CHECK(slurp(prefix + ".pub.pem") == pub_before);
}

TEST_CASE("keygen: hanya salah satu berkas ada -> tetap ditolak, tidak ada setengah pasangan") {
  for (const char* suffix : {".key.pem", ".pub.pem"}) {
    INFO(suffix);
    TempDir d;
    const std::string prefix = (d.path / "k").string();
    std::ofstream(prefix + suffix) << "sisa";
    auto r = run_cli({"keygen", "-algorithm", "ed25519", "-out", prefix});
    CHECK(r.code == 2);
    CHECK(count_files(d.path) == 1);
    CHECK(slurp(prefix + suffix) == "sisa");
  }
}

TEST_CASE("keygen: -force menimpa dan memperketat permission") {
  TempDir d;
  const std::string prefix = (d.path / "k").string();
  auto first = run_cli({"keygen", "-algorithm", "ed25519", "-out", prefix});
  REQUIRE(first.code == 0);
  const std::string before = slurp(prefix + ".key.pem");
  ::chmod((prefix + ".key.pem").c_str(), 0644);

  auto second = run_cli({"keygen", "-algorithm", "ecdsa", "-out", prefix, "-force"});
  REQUIRE(second.code == 0);
  CHECK(slurp(prefix + ".key.pem") != before);
  CHECK(field(second.out, "keyid") != field(first.out, "keyid"));
  CHECK(mode_of(prefix + ".key.pem") == 0600);
  auto priv = crypto::read_private_key(prefix + ".key.pem");
  REQUIRE(priv.has_value());
  CHECK(priv->algorithm() == crypto::Algorithm::EcdsaP256);
}

TEST_CASE("keygen: algoritma tidak dikenal -> exit 2 tanpa berkas") {
  TempDir d;
  const std::string prefix = (d.path / "k").string();
  for (const char* bad : {"rsa", "RSA-PSS", "ed448", "ecdsa-p384", "secp256k1"}) {
    INFO(bad);
    auto r = run_cli({"keygen", "-algorithm", bad, "-out", prefix});
    CHECK(r.code == 2);
    CHECK(r.err.find("algoritma tidak dikenal") != std::string::npos);
  }
  CHECK(count_files(d.path) == 0);
}

TEST_CASE("keygen: direktori keluaran tidak ada -> exit 2, tidak ada berkas") {
  TempDir d;
  const std::string prefix = (d.path / "tidak-ada" / "k").string();
  auto r = run_cli({"keygen", "-algorithm", "ed25519", "-out", prefix});
  CHECK(r.code == 2);
  CHECK(r.out.empty());
  CHECK(count_files(d.path) == 0);
}

TEST_CASE("keygen: pubkey gagal ditulis -> privkey baru dibersihkan") {
  TempDir d;
  const std::string prefix = (d.path / "k").string();
  // Direktori dengan nama berkas pubkey: pembuatan berkas pubkey pasti gagal.
  fs::create_directory(prefix + ".pub.pem");
  // exists() true untuk direktori, jadi tanpa -force ditolak sebelum keygen; pakai -force.
  auto r = run_cli({"keygen", "-algorithm", "ed25519", "-out", prefix, "-force"});
  CHECK(r.code == 2);
  CHECK_FALSE(fs::exists(prefix + ".key.pem"));
  CHECK(fs::is_directory(prefix + ".pub.pem"));
}

TEST_CASE("keygen: berkas terbaca oleh openssl CLI") {
  if (std::system("command -v openssl >/dev/null 2>&1") != 0) {
    MESSAGE("dilewati: openssl CLI tidak ada");
    return;
  }
  for (const auto& c : kCases) {
    if (std::string(c.flag) == "ecdsa-p256") continue;
    INFO(c.flag);
    TempDir d;
    const std::string prefix = (d.path / "k").string();
    REQUIRE(run_cli({"keygen", "-algorithm", c.flag, "-out", prefix}).code == 0);
    CHECK(std::system(("openssl pkey -in '" + prefix + ".key.pem' -noout 2>/dev/null").c_str()) ==
          0);
    CHECK(std::system(
              ("openssl pkey -pubin -in '" + prefix + ".pub.pem' -noout 2>/dev/null").c_str()) ==
          0);
  }
}
