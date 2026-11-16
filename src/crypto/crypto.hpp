#pragma once
/// @file
/// @brief Antarmuka kripto: profil algoritma, sign/verify, dan keyid.
///
/// Fungsi di sini memilih implementasi (ed25519.hpp, ecdsa.hpp, rsa_pss.hpp) berdasarkan profil
/// kunci. Pesan M ditandatangani apa adanya: pemanggil tidak melakukan pre-hash.
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "util/bytes.hpp"
#include "util/result.hpp"

namespace sister_sign::crypto {

// Tipe byte bersama ada di util/bytes.hpp.
using sister_sign::Bytes;
using sister_sign::ByteView;

/// @brief Tiga profil algoritma yang didukung.
///
/// Nama di manifest dan flag `-algorithm`: lihat manifest::algorithm_name().
enum class Algorithm {
  RsaPss,     ///< `rsa-pss-sha256`: RSA 3072, e=65537, PSS SHA-256/MGF1-SHA-256, salt 32
  EcdsaP256,  ///< `ecdsa-p256-sha256`: P-256 + SHA-256, signature r||s 64 byte
  Ed25519     ///< `ed25519`: Ed25519 murni (RFC 8032)
};

/// @brief Ukuran signature RSA-PSS 3072 (byte).
inline constexpr std::size_t kRsaPssSigSize = 384;
/// @brief Ukuran signature ECDSA P-256 (byte): r||s, bukan DER.
inline constexpr std::size_t kEcdsaP256SigSize = 64;
/// @brief Ukuran signature Ed25519 (byte).
inline constexpr std::size_t kEd25519SigSize = 64;

/// @brief Ukuran signature tetap untuk sebuah profil.
/// @param a profil algoritma
/// @return 384, 64, atau 64 byte
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

/// @brief Profil algoritma sebuah privkey. Algoritma diturunkan dari kunci, bukan di-pass manual.
/// @param key privkey
/// @return profil kunci
Algorithm algorithm_of(const PrivateKey& key);
/// @brief Profil algoritma sebuah pubkey.
/// @param key pubkey
/// @return profil kunci
Algorithm algorithm_of(const PublicKey& key);

/// @brief Tandatangani pesan M apa adanya dengan profil kunci.
/// @param key privkey (profil menentukan algoritma)
/// @param message byte yang ditandatangani (untuk sister-sign: byte manifest kanonik)
/// @return signature berukuran signature_size(algorithm_of(key)), atau error
///         (`UNSUPPORTED_ALGORITHM` bila kunci di luar profil, `INPUT_ERROR` bila OpenSSL gagal)
Outcome<Bytes> sign(const PrivateKey& key, ByteView message);

/// @brief Verifikasi signature atas pesan M.
/// @param key pubkey
/// @param message byte yang ditandatangani
/// @param signature signature dalam format sister-sign (untuk ECDSA: r||s 64 byte, DER ditolak)
/// @return true hanya bila signature sah; false untuk panjang salah, signature rusak, atau kunci
///         yang tidak cocok
bool verify(const PublicKey& key, ByteView message, ByteView signature);

/// @brief Identitas pubkey: `hex_lower(SHA-256(DER SPKI))`.
///
/// Tidak bergantung pada format PEM (line ending, lebar baris), karena dihitung dari DER hasil
/// encode ulang OpenSSL.
/// @param key pubkey
/// @return 64 karakter hex huruf kecil, atau `INPUT_ERROR`
Outcome<std::string> keyid(const PublicKey& key);

}  // namespace sister_sign::crypto
