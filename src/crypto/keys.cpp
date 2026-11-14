#include "crypto/keys.hpp"

#include <openssl/evp.h>

namespace sister_sign::crypto {

namespace {

Outcome<Algorithm> classify(const EvpPkey& pkey) {
  if (!pkey) return make_error(Status::InputError, "null key");
  EVP_PKEY* k = pkey.get();
  if (EVP_PKEY_is_a(k, "ED25519")) return Algorithm::Ed25519;
  if (EVP_PKEY_is_a(k, "EC")) {
    char group[64] = {};
    std::size_t len = 0;
    if (EVP_PKEY_get_group_name(k, group, sizeof(group), &len) == 1 &&
        std::string_view(group, len) == "prime256v1") {
      return Algorithm::EcdsaP256;
    }
    return make_error(Status::UnsupportedAlgorithm, "EC key bukan P-256");
  }
  if (EVP_PKEY_is_a(k, "RSA") || EVP_PKEY_is_a(k, "RSA-PSS")) return Algorithm::RsaPss;
  return make_error(Status::UnsupportedAlgorithm, "tipe kunci tidak didukung");
}

}  // namespace

Outcome<PrivateKey> PrivateKey::from_evp(EvpPkey pkey) {
  auto a = classify(pkey);
  if (!a) return std::unexpected(a.error());
  return PrivateKey(std::move(pkey), *a);
}

Outcome<PublicKey> PublicKey::from_evp(EvpPkey pkey) {
  auto a = classify(pkey);
  if (!a) return std::unexpected(a.error());
  return PublicKey(std::move(pkey), *a);
}

}  // namespace sister_sign::crypto
