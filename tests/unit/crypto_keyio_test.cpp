#include <doctest/doctest.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <sys/stat.h>

#include <filesystem>
#include <fstream>
#include <string>

#include "crypto/crypto.hpp"
#include "crypto/keyio.hpp"
#include "test_keys.hpp"

using namespace test;
namespace fs = std::filesystem;

namespace {

std::string mem_string(Bio& bio) {
  char* data = nullptr;
  const long n = BIO_get_mem_data(bio.get(), &data);
  return std::string(data, static_cast<std::size_t>(n));
}

std::string priv_pem(EVP_PKEY* k, const EVP_CIPHER* cipher = nullptr, const char* pass = nullptr) {
  Bio bio = make_mem_bio();
  REQUIRE(PEM_write_bio_PKCS8PrivateKey(bio.get(), k, cipher, pass, pass ? 4 : 0, nullptr,
                                        nullptr) == 1);
  return mem_string(bio);
}

std::string pub_pem(EVP_PKEY* k) {
  Bio bio = make_mem_bio();
  REQUIRE(PEM_write_bio_PUBKEY(bio.get(), k) == 1);
  return mem_string(bio);
}

fs::path temp_dir(const char* name) {
  fs::path d = fs::temp_directory_path() / name;
  fs::remove_all(d);
  fs::create_directories(d);
  return d;
}

Status err_status(const auto& r) { return r.error().status; }

// Permission berkas (9 bit rwx); -1 bila stat gagal.
int mode_of(const fs::path& p) {
  struct stat st;
  if (::stat(p.c_str(), &st) != 0) return -1;
  return static_cast<int>(st.st_mode & 0777);
}

}  // namespace

TEST_CASE("keygen -> PEM -> load -> sign -> verify for all three profiles") {
  for (Algorithm a : {Algorithm::Ed25519, Algorithm::EcdsaP256, Algorithm::RsaPss}) {
    auto kp = generate_keypair(a);
    REQUIRE(kp.has_value());
    CHECK(kp->priv.algorithm() == a);
    CHECK(kp->pub.algorithm() == a);

    auto ppem = private_key_to_pem(kp->priv);
    auto upem = public_key_to_pem(kp->pub);
    REQUIRE(ppem.has_value());
    REQUIRE(upem.has_value());
    const std::string_view priv_text(reinterpret_cast<const char*>(ppem->data()), ppem->size());
    CHECK(priv_text.starts_with("-----BEGIN PRIVATE KEY-----"));
    CHECK(upem->starts_with("-----BEGIN PUBLIC KEY-----"));

    auto priv = parse_private_key_pem(priv_text);
    auto pub = parse_public_key_pem(*upem);
    REQUIRE(priv.has_value());
    REQUIRE(pub.has_value());
    CHECK(priv->algorithm() == a);
    CHECK(pub->algorithm() == a);

    const Bytes msg = bytes_of("hello");
    auto sig = sign(*priv, msg);
    REQUIRE(sig.has_value());
    CHECK(verify(*pub, msg, *sig));
    CHECK(verify(kp->pub, msg, *sig));  // pubkey asli dan hasil load setara

    auto id1 = keyid(kp->pub);
    auto id2 = keyid(*pub);
    REQUIRE(id1.has_value());
    REQUIRE(id2.has_value());
    CHECK(*id1 == *id2);
  }
}

TEST_CASE("public_key_of matches the generated public key") {
  auto kp = generate_keypair(Algorithm::Ed25519);
  REQUIRE(kp.has_value());
  auto pub = public_key_of(kp->priv);
  REQUIRE(pub.has_value());
  CHECK(*keyid(*pub) == *keyid(kp->pub));
}

TEST_CASE("loader rejects keys outside the profile") {
  struct Case {
    const char* name;
    EvpPkey key;
  };
  Case cases[] = {{"RSA 2048", generate_rsa(2048)},
                  {"RSA 2048 e=3", generate_rsa(2048, 3)},
                  {"EC P-384", generate("EC", "secp384r1")},
                  {"EC P-256 via secp256k1", generate("EC", "secp256k1")},
                  {"Ed448", generate("ED448")},
                  {"X25519", generate("X25519")}};
  for (auto& c : cases) {
    CAPTURE(c.name);
    auto priv = parse_private_key_pem(priv_pem(c.key.get()));
    REQUIRE_FALSE(priv.has_value());
    CHECK(err_status(priv) == Status::UnsupportedAlgorithm);
    auto pub = parse_public_key_pem(pub_pem(c.key.get()));
    REQUIRE_FALSE(pub.has_value());
    CHECK(err_status(pub) == Status::UnsupportedAlgorithm);
  }
}

TEST_CASE("loader rejects EC keys with explicit curve parameters") {
  EvpPkeyCtx ctx = make_pkey_ctx("EC");
  REQUIRE(ctx != nullptr);
  REQUIRE(EVP_PKEY_keygen_init(ctx.get()) == 1);
  REQUIRE(EVP_PKEY_CTX_set_group_name(ctx.get(), "prime256v1") == 1);
  REQUIRE(EVP_PKEY_CTX_set_ec_param_enc(ctx.get(), 0) > 0);  // 0 = explicit parameters
  EVP_PKEY* raw = nullptr;
  REQUIRE(EVP_PKEY_keygen(ctx.get(), &raw) == 1);
  EvpPkey key(raw);
  auto r = parse_private_key_pem(priv_pem(key.get()));
  REQUIRE_FALSE(r.has_value());
  CHECK(err_status(r) == Status::UnsupportedAlgorithm);
}

TEST_CASE("loader rejects wrong labels and formats") {
  auto kp = generate_keypair(Algorithm::EcdsaP256);
  REQUIRE(kp.has_value());
  const std::string priv = priv_pem(kp->priv.get());
  const std::string pub = pub_pem(kp->pub.get());

  SUBCASE("public PEM given to the private loader and vice versa") {
    CHECK_FALSE(parse_private_key_pem(pub).has_value());
    CHECK_FALSE(parse_public_key_pem(priv).has_value());
  }
  SUBCASE("traditional EC PRIVATE KEY label") {
    Bio bio = make_mem_bio();
    REQUIRE(PEM_write_bio_PrivateKey_traditional(bio.get(), kp->priv.get(), nullptr, nullptr, 0,
                                                 nullptr, nullptr) == 1);
    const std::string text = mem_string(bio);
    CHECK(text.starts_with("-----BEGIN EC PRIVATE KEY-----"));
    auto r = parse_private_key_pem(text);
    REQUIRE_FALSE(r.has_value());
    CHECK(err_status(r) == Status::FormatError);
  }
  SUBCASE("encrypted PKCS#8") {
    const std::string text = priv_pem(kp->priv.get(), EVP_aes_256_cbc(), "pass");
    CHECK(text.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----"));
    auto r = parse_private_key_pem(text);
    REQUIRE_FALSE(r.has_value());
    CHECK(err_status(r) == Status::FormatError);
  }
  SUBCASE("empty, garbage, truncated") {
    CHECK_FALSE(parse_private_key_pem("").has_value());
    CHECK_FALSE(parse_private_key_pem("not a pem").has_value());
    CHECK_FALSE(parse_private_key_pem(priv.substr(0, priv.size() / 2)).has_value());
    CHECK_FALSE(parse_public_key_pem(pub.substr(0, pub.size() / 2)).has_value());
    auto r = parse_private_key_pem("");
    CHECK(err_status(r) == Status::FormatError);
  }
  SUBCASE("corrupted body") {
    std::string bad = priv;
    bad[40] = bad[40] == 'A' ? 'B' : 'A';
    bad[41] = bad[41] == 'A' ? 'B' : 'A';
    bad[60] = bad[60] == 'A' ? 'B' : 'A';
    CHECK_FALSE(parse_private_key_pem(bad).has_value());
  }
  SUBCASE("two blocks or trailing junk") {
    CHECK_FALSE(parse_private_key_pem(priv + priv).has_value());
    CHECK_FALSE(parse_private_key_pem(priv + "junk").has_value());
    CHECK_FALSE(parse_public_key_pem(pub + pub).has_value());
    CHECK(parse_private_key_pem(priv + "\n\n").has_value());  // whitespace di akhir boleh
  }
  SUBCASE("PEM header lines") {
    std::string with_header = priv;
    with_header.insert(with_header.find('\n') + 1, "Proc-Type: 4,ENCRYPTED\n\n");
    CHECK_FALSE(parse_private_key_pem(with_header).has_value());
  }
  SUBCASE("error messages never contain key material") {
    std::string bad = priv;
    bad[45] ^= 1;
    auto r = parse_private_key_pem(bad);
    if (!r.has_value()) {
      const std::string body = priv.substr(30, 24);
      CHECK(r.error().message.find(body) == std::string::npos);
    }
    auto wrong = parse_public_key_pem(priv);
    REQUIRE_FALSE(wrong.has_value());
    CHECK(wrong.error().message.find(priv.substr(30, 24)) == std::string::npos);
  }
}

TEST_CASE("PEM text is reformat-tolerant for CRLF") {
  auto kp = generate_keypair(Algorithm::Ed25519);
  REQUIRE(kp.has_value());
  std::string pem = pub_pem(kp->pub.get());
  std::string crlf;
  for (char c : pem) {
    if (c == '\n') crlf += '\r';
    crlf += c;
  }
  auto pub = parse_public_key_pem(crlf);
  REQUIRE(pub.has_value());
  CHECK(*keyid(*pub) == *keyid(kp->pub));
}

TEST_CASE("key files: write, read back, no overwrite, permissions") {
  const fs::path dir = temp_dir("sister_sign_keyio_files");
  auto kp = generate_keypair(Algorithm::Ed25519);
  REQUIRE(kp.has_value());
  const fs::path priv_path = dir / "t.key.pem";
  const fs::path pub_path = dir / "t.pub.pem";

  REQUIRE(write_private_key(priv_path, kp->priv).has_value());
  REQUIRE(write_public_key(pub_path, kp->pub).has_value());

  auto priv = read_private_key(priv_path);
  auto pub = read_public_key(pub_path);
  REQUIRE(priv.has_value());
  REQUIRE(pub.has_value());
  const Bytes msg = bytes_of("file roundtrip");
  auto sig = sign(*priv, msg);
  REQUIRE(sig.has_value());
  CHECK(verify(*pub, msg, *sig));

  SUBCASE("existing files are not overwritten by default") {
    auto again = write_private_key(priv_path, kp->priv);
    REQUIRE_FALSE(again.has_value());
    CHECK(again.error().status == Status::InputError);
    auto again_pub = write_public_key(pub_path, kp->pub);
    REQUIRE_FALSE(again_pub.has_value());
    CHECK(again_pub.error().status == Status::InputError);
    // Isi lama tetap utuh.
    CHECK(read_private_key(priv_path).has_value());
  }
  SUBCASE("explicit overwrite works and tightens a loose mode") {
    ::chmod(priv_path.c_str(), 0666);
    auto other = generate_keypair(Algorithm::Ed25519);
    REQUIRE(other.has_value());
    REQUIRE(write_private_key(priv_path, other->priv, true).has_value());
    CHECK(mode_of(priv_path) == 0600);
    auto loaded = read_private_key(priv_path);
    REQUIRE(loaded.has_value());
    auto loaded_pub = public_key_of(*loaded);
    REQUIRE(loaded_pub.has_value());
    CHECK(*keyid(*loaded_pub) == *keyid(other->pub));
  }
  SUBCASE("private key file is not group/world accessible") {
    REQUIRE(mode_of(priv_path) >= 0);
    CHECK((mode_of(priv_path) & 0077) == 0);
    REQUIRE(mode_of(pub_path) >= 0);
    CHECK((mode_of(pub_path) & 0600) == 0600);
  }
  SUBCASE("missing / unwritable paths") {
    auto missing = read_private_key(dir / "nope.pem");
    REQUIRE_FALSE(missing.has_value());
    CHECK(missing.error().status == Status::InputError);
    auto bad_dir = write_private_key(dir / "no_such_dir" / "k.pem", kp->priv);
    REQUIRE_FALSE(bad_dir.has_value());
    CHECK(bad_dir.error().status == Status::InputError);
  }
  SUBCASE("garbage file is a FORMAT_ERROR, not an I/O error") {
    std::ofstream(dir / "bad.pem") << "garbage";
    auto r = read_private_key(dir / "bad.pem");
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().status == Status::FormatError);
  }
  fs::remove_all(dir);
}

TEST_CASE("RSA 3072 key files roundtrip and sign") {
  auto kp = generate_keypair(Algorithm::RsaPss);
  REQUIRE(kp.has_value());
  const fs::path dir = temp_dir("sister_sign_keyio_rsa");
  REQUIRE(write_private_key(dir / "r.key.pem", kp->priv).has_value());
  REQUIRE(write_public_key(dir / "r.pub.pem", kp->pub).has_value());
  auto priv = read_private_key(dir / "r.key.pem");
  auto pub = read_public_key(dir / "r.pub.pem");
  REQUIRE(priv.has_value());
  REQUIRE(pub.has_value());
  auto sig = sign(*priv, bytes_of("rsa"));
  REQUIRE(sig.has_value());
  CHECK(verify(*pub, bytes_of("rsa"), *sig));
  fs::remove_all(dir);
}

TEST_CASE("keygen output is readable by the openssl CLI") {
  if (std::system("openssl version > /dev/null 2>&1") != 0) {
    MESSAGE("openssl CLI tidak ada; cek silang dilewati (dicakup T28 interop)");
    return;
  }
  const fs::path dir = temp_dir("sister_sign_keyio_cli");
  for (Algorithm a : {Algorithm::Ed25519, Algorithm::EcdsaP256}) {
    auto kp = generate_keypair(a);
    REQUIRE(kp.has_value());
    REQUIRE(write_private_key(dir / "k.pem", kp->priv, true).has_value());
    REQUIRE(write_public_key(dir / "p.pem", kp->pub, true).has_value());
    const std::string quiet = " > /dev/null 2>&1";
    CHECK(std::system(
              ("openssl pkey -in " + (dir / "k.pem").string() + " -noout" + quiet).c_str()) == 0);
    CHECK(std::system(("openssl pkey -pubin -in " + (dir / "p.pem").string() + " -noout" + quiet)
                          .c_str()) == 0);
  }
  fs::remove_all(dir);
}
