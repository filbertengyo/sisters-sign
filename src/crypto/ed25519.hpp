#pragma once
/// @file
/// @brief Ed25519 (RFC 8032): EVP_DigestSign satu panggilan, md=NULL.
///
/// Biasanya dipanggil lewat crypto::sign() / crypto::verify().
#include "crypto/crypto.hpp"
#include "crypto/keys.hpp"

namespace sister_sign::crypto {

/// @brief Tandatangani pesan dengan Ed25519.
/// @param key privkey Ed25519
/// @param message pesan
/// @return signature 64 byte, `UNSUPPORTED_ALGORITHM` bila kunci bukan Ed25519, atau
///         `INPUT_ERROR` bila OpenSSL gagal
Outcome<Bytes> ed25519_sign(const PrivateKey& key, ByteView message);
/// @brief Verifikasi signature Ed25519 (harus tepat 64 byte).
/// @param key pubkey Ed25519
/// @param message pesan
/// @param signature signature
/// @return true bila sah
bool ed25519_verify(const PublicKey& key, ByteView message, ByteView signature);

}  // namespace sister_sign::crypto
