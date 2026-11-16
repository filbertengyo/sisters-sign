#pragma once
/// @file
/// @brief RSA-PSS 3072: SHA-256, MGF1-SHA256, salt 32 byte, e = 65537. Signature 384 byte.
///
/// Hash dihitung oleh EVP_DigestSign sendiri (jangan pre-hash di pemanggil). Parameter PSS di-set
/// eksplisit; verifier tidak memakai salt otomatis. Biasanya dipanggil lewat crypto::sign() /
/// crypto::verify().
#include <openssl/evp.h>

#include "crypto/crypto.hpp"
#include "crypto/keys.hpp"

namespace sister_sign::crypto {

/// @brief Cek profil kunci RSA: tipe rsaEncryption, 3072 bit, e = 65537.
///
/// Bisa dicek dari pubkey saja; dipakai juga oleh key I/O dan trust store.
/// @param key kunci OpenSSL (boleh nullptr)
/// @return true bila sesuai profil
bool rsa_pss_profile_ok(EVP_PKEY* key);

/// @brief Tandatangani pesan dengan RSA-PSS.
/// @param key privkey RSA 3072
/// @param message pesan
/// @return signature 384 byte, `UNSUPPORTED_ALGORITHM` bila kunci di luar profil, atau
///         `INPUT_ERROR` bila OpenSSL gagal
Outcome<Bytes> rsa_pss_sign(const PrivateKey& key, ByteView message);
/// @brief Verifikasi signature RSA-PSS dengan salt tepat 32 byte.
/// @param key pubkey RSA 3072
/// @param message pesan
/// @param signature signature 384 byte
/// @return true bila sah
bool rsa_pss_verify(const PublicKey& key, ByteView message, ByteView signature);

}  // namespace sister_sign::crypto
