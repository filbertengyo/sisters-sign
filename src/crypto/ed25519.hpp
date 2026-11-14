#pragma once
// Ed25519 (RFC 8032): EVP_DigestSign satu panggilan, md=NULL. Dipanggil lewat crypto::sign/verify.
#include "crypto/crypto.hpp"
#include "crypto/keys.hpp"

namespace sister_sign::crypto {

Outcome<Bytes> ed25519_sign(const PrivateKey& key, ByteView message);
bool ed25519_verify(const PublicKey& key, ByteView message, ByteView signature);

}  // namespace sister_sign::crypto
