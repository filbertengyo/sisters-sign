#include "crypto/crypto.hpp"

#include "crypto/ecdsa.hpp"
#include "crypto/ed25519.hpp"
#include "crypto/keys.hpp"
#include "crypto/rsa_pss.hpp"

namespace sister_sign::crypto {

Algorithm algorithm_of(const PrivateKey& key) { return key.algorithm(); }
Algorithm algorithm_of(const PublicKey& key) { return key.algorithm(); }

// Dispatch per profil.
Outcome<Bytes> sign(const PrivateKey& key, ByteView message) {
  switch (key.algorithm()) {
    case Algorithm::Ed25519:
      return ed25519_sign(key, message);
    case Algorithm::EcdsaP256:
      return ecdsa_sign(key, message);
    case Algorithm::RsaPss:
      return rsa_pss_sign(key, message);
  }
  return make_error(Status::UnsupportedAlgorithm, "profil tidak dikenal");
}

bool verify(const PublicKey& key, ByteView message, ByteView signature) {
  switch (key.algorithm()) {
    case Algorithm::Ed25519:
      return ed25519_verify(key, message, signature);
    case Algorithm::EcdsaP256:
      return ecdsa_verify(key, message, signature);
    case Algorithm::RsaPss:
      return rsa_pss_verify(key, message, signature);
  }
  return false;
}

}  // namespace sister_sign::crypto
