#include <doctest/doctest.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

#include "crypto/crypto.hpp"
#include "crypto/rsa_pss.hpp"
#include "test_keys.hpp"

using namespace test;

namespace {

// Keygen RSA 3072 butuh beberapa detik: buat sekali, pakai ulang di semua test case.
const EvpPkey& shared_key() {
  static EvpPkey key = generate_rsa(3072);
  return key;
}

PrivateKey priv_of(const EvpPkey& k) {
  EVP_PKEY_up_ref(k.get());
  auto r = PrivateKey::from_evp(EvpPkey(k.get()));
  REQUIRE(r.has_value());
  return std::move(*r);
}

PublicKey pub_of(const EvpPkey& k) {
  auto r = PublicKey::from_evp(public_only(k.get()));
  REQUIRE(r.has_value());
  return std::move(*r);
}

// Signature PSS dengan parameter sembarang, untuk membuktikan verify kita ketat.
Bytes pss_sign_raw(const EvpPkey& key, ByteView msg, int saltlen, const EVP_MD* mgf1) {
  EvpMdCtx ctx = make_md_ctx();
  EVP_PKEY_CTX* pctx = nullptr;
  REQUIRE(EVP_DigestSignInit(ctx.get(), &pctx, EVP_sha256(), nullptr, key.get()) == 1);
  REQUIRE(EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) > 0);
  REQUIRE(EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, saltlen) > 0);
  REQUIRE(EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, mgf1) > 0);
  Bytes sig(384);
  std::size_t len = sig.size();
  REQUIRE(EVP_DigestSign(ctx.get(), sig.data(), &len, msg.data(), msg.size()) == 1);
  sig.resize(len);
  return sig;
}

bool has_cli() { return std::system("openssl version > /dev/null 2>&1") == 0; }

void write_file(const std::filesystem::path& p, const void* data, std::size_t n) {
  std::ofstream(p, std::ios::binary).write(static_cast<const char*>(data), static_cast<long>(n));
}

}  // namespace

TEST_CASE("RSA-PSS profile check") {
  CHECK(rsa_pss_profile_ok(shared_key().get()));
  CHECK(rsa_pss_profile_ok(public_only(shared_key().get()).get()));
  EvpPkey small = generate_rsa(2048);
  CHECK_FALSE(rsa_pss_profile_ok(small.get()));
  EvpPkey e3 = generate_rsa(2048, 3);
  CHECK_FALSE(rsa_pss_profile_ok(e3.get()));
  EvpPkey ed = generate("ED25519");
  CHECK_FALSE(rsa_pss_profile_ok(ed.get()));
  CHECK_FALSE(rsa_pss_profile_ok(nullptr));
}

TEST_CASE("RSA-PSS sign -> verify OK, signature is 384 bytes") {
  PrivateKey priv = priv_of(shared_key());
  PublicKey pub = pub_of(shared_key());
  CHECK(priv.algorithm() == Algorithm::RsaPss);
  const Bytes empty;
  const Bytes big(1u << 20, 0x5A);
  for (const Bytes* m : {&empty, &big}) {
    auto sig = sign(priv, *m);
    REQUIRE(sig.has_value());
    CHECK(sig->size() == kRsaPssSigSize);
    CHECK(verify(pub, *m, *sig));
  }
}

TEST_CASE("RSA-PSS is probabilistic: same message -> different signatures, both valid") {
  PrivateKey priv = priv_of(shared_key());
  PublicKey pub = pub_of(shared_key());
  const Bytes m = bytes_of("same message");
  auto a = sign(priv, m);
  auto b = sign(priv, m);
  REQUIRE(a.has_value());
  REQUIRE(b.has_value());
  CHECK(*a != *b);
  CHECK(verify(pub, m, *a));
  CHECK(verify(pub, m, *b));
}

TEST_CASE("RSA-PSS rejects tampering") {
  PrivateKey priv = priv_of(shared_key());
  PublicKey pub = pub_of(shared_key());
  const Bytes m = bytes_of("manifest bytes");
  auto sig = sign(priv, m);
  REQUIRE(sig.has_value());

  SUBCASE("flip 1 bit signature / message") {
    for (std::size_t bit : {std::size_t{0}, std::size_t{1500}, std::size_t{3071}}) {
      Bytes bad = *sig;
      bad[bit / 8] ^= static_cast<std::uint8_t>(1u << (bit % 8));
      CHECK_FALSE(verify(pub, m, bad));
    }
    Bytes bad_msg = m;
    bad_msg[0] ^= 1;
    CHECK_FALSE(verify(pub, bad_msg, *sig));
  }
  SUBCASE("signature length 383 / 385 / 0") {
    Bytes shorter(sig->begin(), sig->end() - 1);
    Bytes longer = *sig;
    longer.push_back(0);
    CHECK_FALSE(verify(pub, m, shorter));
    CHECK_FALSE(verify(pub, m, longer));
    CHECK_FALSE(verify(pub, m, Bytes{}));
  }
  SUBCASE("different 3072-bit key") {
    EvpPkey other = generate_rsa(3072);
    CHECK_FALSE(verify(pub_of(other), m, *sig));
  }
}

TEST_CASE("RSA-PSS verify enforces salt 32 and MGF1-SHA256") {
  const EvpPkey& key = shared_key();
  PublicKey pub = pub_of(key);
  const Bytes m = bytes_of("parameter check");

  CHECK(verify(pub, m, pss_sign_raw(key, m, 32, EVP_sha256())));  // pembanding: lolos
  CHECK_FALSE(verify(pub, m, pss_sign_raw(key, m, 20, EVP_sha256())));
  CHECK_FALSE(verify(pub, m, pss_sign_raw(key, m, 64, EVP_sha256())));
  CHECK_FALSE(verify(pub, m, pss_sign_raw(key, m, RSA_PSS_SALTLEN_MAX, EVP_sha256())));
  CHECK_FALSE(verify(pub, m, pss_sign_raw(key, m, 32, EVP_sha1())));
}

TEST_CASE("RSA keys outside the profile are rejected when used") {
  EvpPkey small = generate_rsa(2048);
  auto priv = PrivateKey::from_evp(std::move(small));
  REQUIRE(priv.has_value());
  auto sig = sign(*priv, bytes_of("x"));
  REQUIRE_FALSE(sig.has_value());
  CHECK(sig.error().status == Status::UnsupportedAlgorithm);

  // Signature sah dari kunci 2048 (256 byte) tidak mungkin lolos; panjang 384 pun tidak.
  EvpPkey small2 = generate_rsa(2048);
  PublicKey small_pub = pub_of(small2);
  CHECK_FALSE(verify(small_pub, bytes_of("x"), Bytes(384, 1)));
}

TEST_CASE("RSA-PSS rejects keys of another profile") {
  Pair ed = make_pair("ED25519");
  CHECK_FALSE(rsa_pss_sign(ed.priv, bytes_of("x")).has_value());
  CHECK_FALSE(rsa_pss_verify(ed.pub, bytes_of("x"), Bytes(384, 1)));
}

TEST_CASE("RSA-PSS interop with the openssl CLI (both directions)") {
  if (!has_cli()) {
    MESSAGE("openssl CLI tidak ada; cek silang dilewati (dicakup T28 interop)");
    return;
  }
  namespace fs = std::filesystem;
  const fs::path dir = fs::temp_directory_path() / "sister_sign_rsa_xcheck";
  fs::create_directories(dir);
  const EvpPkey& key = shared_key();
  PrivateKey priv = priv_of(key);
  PublicKey pub = pub_of(key);
  const Bytes m = bytes_of("cross-check message");

  {
    Bio bio = make_mem_bio();
    REQUIRE(PEM_write_bio_PUBKEY(bio.get(), pub.get()) == 1);
    char* data = nullptr;
    const long n = BIO_get_mem_data(bio.get(), &data);
    write_file(dir / "pub.pem", data, static_cast<std::size_t>(n));
  }
  {
    Bio bio = make_mem_bio();
    REQUIRE(PEM_write_bio_PrivateKey(bio.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr) ==
            1);
    char* data = nullptr;
    const long n = BIO_get_mem_data(bio.get(), &data);
    write_file(dir / "priv.pem", data, static_cast<std::size_t>(n));
  }
  write_file(dir / "msg.bin", m.data(), m.size());

  const std::string opts =
      " -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -sigopt rsa_mgf1_md:sha256";
  const std::string quiet = " > /dev/null 2>&1";

  // Arah 1: signature kita -> diverifikasi openssl CLI.
  auto sig = sign(priv, m);
  REQUIRE(sig.has_value());
  write_file(dir / "sig.bin", sig->data(), sig->size());
  const std::string verify_cmd =
      "openssl dgst -sha256" + opts + " -verify " + (dir / "pub.pem").string() + " -signature " +
      (dir / "sig.bin").string() + " " + (dir / "msg.bin").string() + quiet;
  CHECK(std::system(verify_cmd.c_str()) == 0);

  // Arah 2: signature openssl CLI -> diverifikasi kita.
  const std::string sign_cmd =
      "openssl dgst -sha256" + opts + " -sign " + (dir / "priv.pem").string() + " -out " +
      (dir / "cli_sig.bin").string() + " " + (dir / "msg.bin").string() + quiet;
  REQUIRE(std::system(sign_cmd.c_str()) == 0);
  std::ifstream in(dir / "cli_sig.bin", std::ios::binary);
  Bytes cli_sig((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  REQUIRE(cli_sig.size() == kRsaPssSigSize);
  CHECK(verify(pub, m, cli_sig));

  // Pesan lain harus ditolak oleh CLI.
  write_file(dir / "msg.bin", "tampered", 8);
  CHECK(std::system(verify_cmd.c_str()) != 0);
  fs::remove_all(dir);
}
