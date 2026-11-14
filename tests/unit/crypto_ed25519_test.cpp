#include <doctest/doctest.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

#include "crypto/crypto.hpp"
#include "crypto/keys.hpp"

using namespace sister_sign;
using namespace sister_sign::crypto;

namespace {

EvpPkey generate(const char* algorithm, const char* group = nullptr) {
  EvpPkeyCtx ctx = make_pkey_ctx(algorithm);
  REQUIRE(ctx != nullptr);
  REQUIRE(EVP_PKEY_keygen_init(ctx.get()) == 1);
  if (group != nullptr) {
    REQUIRE(EVP_PKEY_CTX_set_group_name(ctx.get(), group) == 1);
  }
  EVP_PKEY* raw = nullptr;
  REQUIRE(EVP_PKEY_keygen(ctx.get(), &raw) == 1);
  return EvpPkey(raw);
}

// Kunci publik murni (tanpa bagian privat) lewat roundtrip SPKI DER.
EvpPkey public_only(EVP_PKEY* key) {
  unsigned char* der = nullptr;
  int len = i2d_PUBKEY(key, &der);
  REQUIRE(len > 0);
  const unsigned char* p = der;
  EvpPkey pub(d2i_PUBKEY(nullptr, &p, len));
  OPENSSL_free(der);
  REQUIRE(pub != nullptr);
  return pub;
}

struct Pair {
  PrivateKey priv;
  PublicKey pub;
};

Pair ed25519_pair() {
  EvpPkey k = generate("ED25519");
  EvpPkey pub = public_only(k.get());
  auto priv = PrivateKey::from_evp(std::move(k));
  auto pubk = PublicKey::from_evp(std::move(pub));
  REQUIRE(priv.has_value());
  REQUIRE(pubk.has_value());
  return Pair{std::move(*priv), std::move(*pubk)};
}

Bytes bytes_of(std::string_view s) { return Bytes(s.begin(), s.end()); }

}  // namespace

TEST_CASE("Ed25519 key classification") {
  Pair p = ed25519_pair();
  CHECK(p.priv.algorithm() == Algorithm::Ed25519);
  CHECK(algorithm_of(p.pub) == Algorithm::Ed25519);

  auto ec = PrivateKey::from_evp(generate("EC", "prime256v1"));
  REQUIRE(ec.has_value());
  CHECK(ec->algorithm() == Algorithm::EcdsaP256);

  auto p384 = PrivateKey::from_evp(generate("EC", "secp384r1"));
  REQUIRE_FALSE(p384.has_value());
  CHECK(p384.error().status == Status::UnsupportedAlgorithm);

  auto x = PrivateKey::from_evp(generate("X25519"));
  REQUIRE_FALSE(x.has_value());
  CHECK(x.error().status == Status::UnsupportedAlgorithm);
}

TEST_CASE("Ed25519 sign -> verify OK") {
  Pair p = ed25519_pair();
  const Bytes empty;
  const Bytes one{0x42};
  const Bytes big(1u << 20, 0xAB);
  for (const Bytes* m : {&empty, &one, &big}) {
    auto sig = sign(p.priv, *m);
    REQUIRE(sig.has_value());
    CHECK(sig->size() == kEd25519SigSize);
    CHECK(verify(p.pub, *m, *sig));
  }
}

TEST_CASE("Ed25519 rejects tampering") {
  Pair p = ed25519_pair();
  const Bytes msg = bytes_of("manifest bytes");
  auto sig = sign(p.priv, msg);
  REQUIRE(sig.has_value());

  SUBCASE("flip 1 bit signature") {
    for (std::size_t bit : {std::size_t{0}, std::size_t{255}, std::size_t{511}}) {
      Bytes bad = *sig;
      bad[bit / 8] ^= static_cast<std::uint8_t>(1u << (bit % 8));
      CHECK_FALSE(verify(p.pub, msg, bad));
    }
  }
  SUBCASE("flip 1 bit message") {
    Bytes bad = msg;
    bad[0] ^= 1;
    CHECK_FALSE(verify(p.pub, bad, *sig));
  }
  SUBCASE("signature length 63 / 65 / 0") {
    Bytes shorter(sig->begin(), sig->end() - 1);
    Bytes longer = *sig;
    longer.push_back(0);
    CHECK_FALSE(verify(p.pub, msg, shorter));
    CHECK_FALSE(verify(p.pub, msg, longer));
    CHECK_FALSE(verify(p.pub, msg, Bytes{}));
  }
  SUBCASE("different key") {
    Pair other = ed25519_pair();
    CHECK_FALSE(verify(other.pub, msg, *sig));
  }
}

TEST_CASE("Ed25519 is deterministic (RFC 8032)") {
  Pair p = ed25519_pair();
  const Bytes msg = bytes_of("same message");
  auto a = sign(p.priv, msg);
  auto b = sign(p.priv, msg);
  REQUIRE(a.has_value());
  REQUIRE(b.has_value());
  CHECK(*a == *b);
}

TEST_CASE("Ed25519 signature verifies with the openssl CLI") {
  if (std::system("openssl version > /dev/null 2>&1") != 0) {
    MESSAGE("openssl CLI tidak ada; cek silang dilewati (dicakup T28 interop)");
    return;
  }
  namespace fs = std::filesystem;
  const fs::path dir = fs::temp_directory_path() / "sister_sign_ed25519_xcheck";
  fs::create_directories(dir);

  Pair p = ed25519_pair();
  const Bytes msg = bytes_of("cross-check message");
  auto sig = sign(p.priv, msg);
  REQUIRE(sig.has_value());

  {
    Bio bio = make_mem_bio();
    REQUIRE(PEM_write_bio_PUBKEY(bio.get(), p.pub.get()) == 1);
    char* data = nullptr;
    long n = BIO_get_mem_data(bio.get(), &data);
    std::ofstream(dir / "pub.pem", std::ios::binary).write(data, n);
  }
  std::ofstream(dir / "msg.bin", std::ios::binary)
      .write(reinterpret_cast<const char*>(msg.data()), static_cast<std::streamsize>(msg.size()));
  std::ofstream(dir / "sig.bin", std::ios::binary)
      .write(reinterpret_cast<const char*>(sig->data()), static_cast<std::streamsize>(sig->size()));

  const std::string cmd = "openssl pkeyutl -verify -rawin -pubin -inkey " +
                          (dir / "pub.pem").string() + " -in " + (dir / "msg.bin").string() +
                          " -sigfile " + (dir / "sig.bin").string() + " > /dev/null 2>&1";
  CHECK(std::system(cmd.c_str()) == 0);

  // Pesan beda harus ditolak oleh CLI juga.
  std::ofstream(dir / "msg.bin", std::ios::binary) << "tampered";
  CHECK(std::system(cmd.c_str()) != 0);
  fs::remove_all(dir);
}

TEST_CASE("sign/verify reject keys of another profile") {
  auto ec = PrivateKey::from_evp(generate("EC", "prime256v1"));
  REQUIRE(ec.has_value());
  auto r = sign(*ec, bytes_of("x"));
  CHECK_FALSE(r.has_value());  // ECDSA belum diimplementasi (T08)
}
