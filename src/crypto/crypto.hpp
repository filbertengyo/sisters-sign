#pragma once
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "util/result.hpp"

namespace sister_sign::crypto {

using Bytes = std::vector<std::uint8_t>;
using ByteView = std::span<const std::uint8_t>;

enum class Algorithm { RsaPss, EcdsaP256, Ed25519 };

// Ukuran signature per profil.
inline constexpr std::size_t kRsaPssSigSize = 384;
// ECDSA: r||s (bukan DER).
inline constexpr std::size_t kEcdsaP256SigSize = 64;
inline constexpr std::size_t kEd25519SigSize = 64;

constexpr std::size_t signature_size(Algorithm a) {
  switch (a) {
    case Algorithm::RsaPss:
      return kRsaPssSigSize;
    case Algorithm::EcdsaP256:
      return kEcdsaP256SigSize;
    case Algorithm::Ed25519:
      return kEd25519SigSize;
  }
  return 0;
}

// Dibungkus RAII di crypto/raii.hpp
class PrivateKey;
class PublicKey;

// Algoritma diturunkan dari kunci, bukan di-pass manual.
Algorithm algorithm_of(const PrivateKey& key);
Algorithm algorithm_of(const PublicKey& key);

// Sign pesan M apa adanya.
Outcome<Bytes> sign(const PrivateKey& key, ByteView message);

// false untuk sig panjang salah, sig rusak, atau kunci tidak cocok.
bool verify(const PublicKey& key, ByteView message, ByteView signature);

// hex_lower(SHA-256(DER SPKI)), 64 karakter.
Outcome<std::string> keyid(const PublicKey& key);

}  // namespace sister_sign::crypto
