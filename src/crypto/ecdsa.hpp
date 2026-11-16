#pragma once
/// @file
/// @brief ECDSA P-256 + SHA-256 dengan signature tetap 64 byte.
///
/// Format signature: r||s, masing-masing 32 byte big-endian. OpenSSL menghasilkan DER;
/// konversinya ada di ecdsa.cpp (lihat docs/spike-b.md). Biasanya dipanggil lewat crypto::sign() /
/// crypto::verify().
#include "crypto/crypto.hpp"
#include "crypto/keys.hpp"

namespace sister_sign::crypto {

/// @brief Tandatangani pesan dengan ECDSA P-256 + SHA-256.
/// @param key privkey P-256
/// @param message pesan (di-hash SHA-256 di dalam)
/// @return signature r||s 64 byte, `UNSUPPORTED_ALGORITHM` bila kunci bukan P-256, atau
///         `INPUT_ERROR` bila OpenSSL gagal
Outcome<Bytes> ecdsa_sign(const PrivateKey& key, ByteView message);
/// @brief Verifikasi signature r||s. DER mentah (~70 byte) ditolak karena panjangnya bukan 64.
/// @param key pubkey P-256
/// @param message pesan
/// @param signature signature r||s
/// @return true bila sah
bool ecdsa_verify(const PublicKey& key, ByteView message, ByteView signature);

/// @brief Konversi signature DER ke r||s. Diekspos untuk pengujian dan interop (T28).
/// @param der signature ASN.1 DER
/// @return r||s 64 byte, atau `INVALID_SIGNATURE` bila DER tidak sah
Outcome<Bytes> ecdsa_der_to_raw(ByteView der);
/// @brief Konversi signature r||s ke DER.
/// @param raw r||s 64 byte
/// @return DER, `INVALID_SIGNATURE` bila panjang salah atau r/s nol, atau `INPUT_ERROR` bila
///         OpenSSL gagal
Outcome<Bytes> ecdsa_raw_to_der(ByteView raw);

}  // namespace sister_sign::crypto
