#include <doctest/doctest.h>
#include <openssl/bn.h>
#include <openssl/pem.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <set>
#include <string>

#include "crypto/crypto.hpp"
#include "crypto/ecdsa.hpp"
#include "test_keys.hpp"

using namespace test;

namespace {

// P-256 group order n, big-endian.
constexpr std::uint8_t kOrder[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51};

Bytes message(std::size_t i) {
  Bytes m(1 + i % 97);
  for (std::size_t k = 0; k < m.size(); ++k) m[k] = static_cast<std::uint8_t>(i * 31 + k * 7);
  return m;
}

}  // namespace

TEST_CASE("ECDSA sign -> verify OK (100 messages)") {
  Pair p = ecdsa_pair();
  for (std::size_t i = 0; i < 100; ++i) {
    const Bytes m = message(i);
    auto sig = sign(p.priv, m);
    REQUIRE(sig.has_value());
    CHECK(sig->size() == kEcdsaP256SigSize);
    CHECK(verify(p.pub, m, *sig));
  }
}

TEST_CASE("ECDSA empty message") {
  Pair p = ecdsa_pair();
  auto sig = sign(p.priv, Bytes{});
  REQUIRE(sig.has_value());
  CHECK(verify(p.pub, Bytes{}, *sig));
}

TEST_CASE("ECDSA rejects malformed signatures") {
  Pair p = ecdsa_pair();
  const Bytes m = bytes_of("manifest bytes");
  auto sig = sign(p.priv, m);
  REQUIRE(sig.has_value());

  SUBCASE("length 63 / 65 / 0") {
    Bytes shorter(sig->begin(), sig->end() - 1);
    Bytes longer = *sig;
    longer.push_back(0);
    CHECK_FALSE(verify(p.pub, m, shorter));
    CHECK_FALSE(verify(p.pub, m, longer));
    CHECK_FALSE(verify(p.pub, m, Bytes{}));
  }
  SUBCASE("raw DER is rejected") {
    auto der = ecdsa_raw_to_der(*sig);
    REQUIRE(der.has_value());
    CHECK(der->size() >= 68);
    CHECK_FALSE(verify(p.pub, m, *der));
  }
  SUBCASE("r = 0 or s = 0") {
    Bytes zero_r = *sig;
    std::fill(zero_r.begin(), zero_r.begin() + 32, 0);
    Bytes zero_s = *sig;
    std::fill(zero_s.begin() + 32, zero_s.end(), 0);
    CHECK_FALSE(verify(p.pub, m, zero_r));
    CHECK_FALSE(verify(p.pub, m, zero_s));
  }
  SUBCASE("r = n or s = n") {
    Bytes r_n(kOrder, kOrder + 32);
    r_n.insert(r_n.end(), sig->begin() + 32, sig->end());
    Bytes s_n(sig->begin(), sig->begin() + 32);
    s_n.insert(s_n.end(), kOrder, kOrder + 32);
    CHECK_FALSE(verify(p.pub, m, r_n));
    CHECK_FALSE(verify(p.pub, m, s_n));
    Bytes all_ff(64, 0xFF);
    CHECK_FALSE(verify(p.pub, m, all_ff));
  }
  SUBCASE("flip 1 bit signature / message") {
    for (std::size_t bit : {std::size_t{0}, std::size_t{255}, std::size_t{256}, std::size_t{511}}) {
      Bytes bad = *sig;
      bad[bit / 8] ^= static_cast<std::uint8_t>(1u << (bit % 8));
      CHECK_FALSE(verify(p.pub, m, bad));
    }
    Bytes bad_msg = m;
    bad_msg[0] ^= 1;
    CHECK_FALSE(verify(p.pub, bad_msg, *sig));
  }
  SUBCASE("different key") {
    Pair other = ecdsa_pair();
    CHECK_FALSE(verify(other.pub, m, *sig));
  }
}

TEST_CASE("ECDSA is deterministic (RFC 6979)") {
  Pair p = ecdsa_pair();
  const Bytes m = bytes_of("same message");
  auto a = sign(p.priv, m);
  auto b = sign(p.priv, m);
  REQUIRE(a.has_value());
  REQUIRE(b.has_value());
  CHECK(*a == *b);
  CHECK(verify(p.pub, m, *a));
  // Pesan beda -> signature beda.
  auto c = sign(p.priv, bytes_of("other message"));
  REQUIRE(c.has_value());
  CHECK(*c != *a);
}

TEST_CASE("DER <-> r||s: 1000 signatures roundtrip, DER length varies") {
  Pair p = ecdsa_pair();
  std::set<std::size_t> der_lengths;
  for (std::size_t i = 0; i < 1000; ++i) {
    const Bytes m = message(i);

    // DER langsung dari OpenSSL (nonce acak), bukan lewat ecdsa_sign.
    EvpMdCtx ctx = make_md_ctx();
    REQUIRE(EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr, p.priv.get()) == 1);
    std::size_t der_len = 0;
    REQUIRE(EVP_DigestSign(ctx.get(), nullptr, &der_len, m.data(), m.size()) == 1);
    Bytes der(der_len);
    REQUIRE(EVP_DigestSign(ctx.get(), der.data(), &der_len, m.data(), m.size()) == 1);
    der.resize(der_len);
    der_lengths.insert(der.size());

    auto raw = ecdsa_der_to_raw(der);
    REQUIRE(raw.has_value());
    CHECK(raw->size() == 64);
    CHECK(verify(p.pub, m, *raw));
    auto back = ecdsa_raw_to_der(*raw);
    REQUIRE(back.has_value());
    CHECK(*back == der);  // DER kanonik: konversi bolak-balik identik
  }
  // DER panjangnya variabel, r||s selalu 64: itu alasan konversi ini wajib.
  CHECK(der_lengths.size() > 1);
  MESSAGE("distinct DER lengths: " << der_lengths.size());
}

TEST_CASE("ECDSA der_to_raw rejects garbage") {
  CHECK_FALSE(ecdsa_der_to_raw(Bytes{}).has_value());
  CHECK_FALSE(ecdsa_der_to_raw(Bytes{0x30, 0x00}).has_value());
  CHECK_FALSE(ecdsa_der_to_raw(bytes_of("not der at all")).has_value());
  // DER valid + byte sisa di belakang harus ditolak.
  Pair p = ecdsa_pair();
  auto sig = sign(p.priv, bytes_of("x"));
  REQUIRE(sig.has_value());
  auto der = ecdsa_raw_to_der(*sig);
  REQUIRE(der.has_value());
  Bytes trailing = *der;
  trailing.push_back(0);
  CHECK_FALSE(ecdsa_der_to_raw(trailing).has_value());
}

TEST_CASE("ECDSA signature verifies with the openssl CLI after converting back to DER") {
  if (std::system("openssl version > /dev/null 2>&1") != 0) {
    MESSAGE("openssl CLI tidak ada; cek silang dilewati (dicakup T28 interop)");
    return;
  }
  namespace fs = std::filesystem;
  const fs::path dir = fs::temp_directory_path() / "sister_sign_ecdsa_xcheck";
  fs::create_directories(dir);

  Pair p = ecdsa_pair();
  const Bytes m = bytes_of("cross-check message");
  auto sig = sign(p.priv, m);
  REQUIRE(sig.has_value());
  auto der = ecdsa_raw_to_der(*sig);
  REQUIRE(der.has_value());

  {
    Bio bio = make_mem_bio();
    REQUIRE(PEM_write_bio_PUBKEY(bio.get(), p.pub.get()) == 1);
    char* data = nullptr;
    const long n = BIO_get_mem_data(bio.get(), &data);
    std::ofstream(dir / "pub.pem", std::ios::binary).write(data, n);
  }
  std::ofstream(dir / "msg.bin", std::ios::binary)
      .write(reinterpret_cast<const char*>(m.data()), static_cast<std::streamsize>(m.size()));
  std::ofstream(dir / "sig.der", std::ios::binary)
      .write(reinterpret_cast<const char*>(der->data()), static_cast<std::streamsize>(der->size()));

  const std::string cmd = "openssl dgst -sha256 -verify " + (dir / "pub.pem").string() +
                          " -signature " + (dir / "sig.der").string() + " " +
                          (dir / "msg.bin").string() + " > /dev/null 2>&1";
  CHECK(std::system(cmd.c_str()) == 0);

  std::ofstream(dir / "msg.bin", std::ios::binary) << "tampered";
  CHECK(std::system(cmd.c_str()) != 0);
  fs::remove_all(dir);
}

TEST_CASE("sign/verify reject keys of another profile") {
  Pair ed = make_pair("ED25519");
  CHECK_FALSE(ecdsa_sign(ed.priv, bytes_of("x")).has_value());
  Pair ec = ecdsa_pair();
  CHECK_FALSE(ecdsa_verify(ed.pub, bytes_of("x"), Bytes(64, 1)));
  CHECK(ec.priv.algorithm() == Algorithm::EcdsaP256);
}
