#pragma once
// Helper pembuat kunci untuk unit test crypto.
#include <doctest/doctest.h>
#include <openssl/x509.h>

#include <string_view>
#include <utility>

#include "crypto/keys.hpp"
#include "crypto/raii.hpp"

namespace test {

using namespace sister_sign;
using namespace sister_sign::crypto;

inline EvpPkey generate(const char* algorithm, const char* group = nullptr) {
  EvpPkeyCtx ctx = make_pkey_ctx(algorithm);
  REQUIRE(ctx != nullptr);
  REQUIRE(EVP_PKEY_keygen_init(ctx.get()) == 1);
  if (group != nullptr) REQUIRE(EVP_PKEY_CTX_set_group_name(ctx.get(), group) == 1);
  EVP_PKEY* raw = nullptr;
  REQUIRE(EVP_PKEY_keygen(ctx.get(), &raw) == 1);
  return EvpPkey(raw);
}

// Kunci publik murni lewat roundtrip SPKI DER.
inline EvpPkey public_only(EVP_PKEY* key) {
  unsigned char* der = nullptr;
  const int len = i2d_PUBKEY(key, &der);
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

inline Pair make_pair(const char* algorithm, const char* group = nullptr) {
  EvpPkey k = generate(algorithm, group);
  EvpPkey pub = public_only(k.get());
  auto priv = PrivateKey::from_evp(std::move(k));
  auto pubk = PublicKey::from_evp(std::move(pub));
  REQUIRE(priv.has_value());
  REQUIRE(pubk.has_value());
  return Pair{std::move(*priv), std::move(*pubk)};
}

inline Pair ecdsa_pair() { return make_pair("EC", "prime256v1"); }

inline Bytes bytes_of(std::string_view s) { return Bytes(s.begin(), s.end()); }

}  // namespace test
