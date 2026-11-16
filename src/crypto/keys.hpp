#pragma once
/// @file
/// @brief Pembungkus kunci dengan profil algoritma yang sudah diklasifikasi.
///
/// Pembacaan/penulisan PEM dan validasi parameter penuh (RSA 3072/e=65537, dll.) ada di
/// keyio.hpp; di sini hanya klasifikasi tipe kunci.
#include <utility>

#include "crypto/crypto.hpp"
#include "crypto/raii.hpp"

namespace sister_sign::crypto {

/// @brief Privkey OpenSSL milik sendiri beserta profilnya. Hanya bisa dipindah (move).
///
/// Buat lewat read_private_key(), parse_private_key_pem(), atau generate_keypair().
class PrivateKey {
 public:
  /// @brief Bungkus kunci OpenSSL.
  /// @param pkey kunci (kepemilikan dipindah)
  /// @return kunci, atau `UNSUPPORTED_ALGORITHM` bila tipe kunci di luar tiga profil
  static Outcome<PrivateKey> from_evp(EvpPkey pkey);

  /// @brief Profil algoritma kunci.
  Algorithm algorithm() const noexcept { return algorithm_; }
  /// @brief Pointer OpenSSL (tetap dimiliki objek ini).
  EVP_PKEY* get() const noexcept { return pkey_.get(); }

 private:
  PrivateKey(EvpPkey pkey, Algorithm a) : pkey_(std::move(pkey)), algorithm_(a) {}
  EvpPkey pkey_;
  Algorithm algorithm_;
};

/// @brief Pubkey OpenSSL milik sendiri beserta profilnya. Hanya bisa dipindah (move).
///
/// Buat lewat read_public_key(), parse_public_key_pem(), atau public_key_of().
class PublicKey {
 public:
  /// @brief Bungkus kunci OpenSSL.
  /// @param pkey kunci (kepemilikan dipindah)
  /// @return kunci, atau `UNSUPPORTED_ALGORITHM` bila tipe kunci di luar tiga profil
  static Outcome<PublicKey> from_evp(EvpPkey pkey);

  /// @brief Profil algoritma kunci.
  Algorithm algorithm() const noexcept { return algorithm_; }
  /// @brief Pointer OpenSSL (tetap dimiliki objek ini).
  EVP_PKEY* get() const noexcept { return pkey_.get(); }

 private:
  PublicKey(EvpPkey pkey, Algorithm a) : pkey_(std::move(pkey)), algorithm_(a) {}
  EvpPkey pkey_;
  Algorithm algorithm_;
};

}  // namespace sister_sign::crypto
