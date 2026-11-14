#pragma once
// ECDSA P-256 + SHA-256 dengan signature tetap 64 byte (r||s, masing-masing 32 byte big-endian).
// OpenSSL menghasilkan DER; konversinya ada di ecdsa.cpp (lihat docs/spike-b.md).
#include "crypto/crypto.hpp"
#include "crypto/keys.hpp"

namespace sister_sign::crypto {

Outcome<Bytes> ecdsa_sign(const PrivateKey& key, ByteView message);
bool ecdsa_verify(const PublicKey& key, ByteView message, ByteView signature);

// Konversi format. Diekspos untuk pengujian dan interop (T28).
Outcome<Bytes> ecdsa_der_to_raw(ByteView der);  // DER -> r||s (64 byte)
Outcome<Bytes> ecdsa_raw_to_der(ByteView raw);  // r||s -> DER; tolak r/s nol

}  // namespace sister_sign::crypto
