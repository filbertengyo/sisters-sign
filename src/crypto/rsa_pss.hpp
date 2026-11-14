#pragma once
// RSA-PSS 3072: SHA-256, MGF1-SHA256, salt 32 byte, e = 65537. Signature 384 byte.
// Hash dihitung oleh EVP_DigestSign sendiri (jangan pre-hash di pemanggil).
#include <openssl/evp.h>

#include "crypto/crypto.hpp"
#include "crypto/keys.hpp"

namespace sister_sign::crypto {

// Profil kunci RSA: tipe rsaEncryption, 3072 bit, e = 65537. Bisa dicek dari pubkey saja.
// Dipakai juga oleh key I/O (T11) dan trust store (T14).
bool rsa_pss_profile_ok(EVP_PKEY* key);

Outcome<Bytes> rsa_pss_sign(const PrivateKey& key, ByteView message);
bool rsa_pss_verify(const PublicKey& key, ByteView message, ByteView signature);

}  // namespace sister_sign::crypto
