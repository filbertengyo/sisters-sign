#pragma once
// Pembungkus kunci dengan profil algoritma yang sudah diklasifikasi. Pembacaan/penulisan PEM dan
// validasi parameter penuh (RSA 3072/e=65537, dll.) ditambahkan di T11; di sini hanya
// klasifikasi tipe kunci.
#include <utility>

#include "crypto/crypto.hpp"
#include "crypto/raii.hpp"

namespace sister_sign::crypto {

class PrivateKey {
 public:
  // Menolak tipe kunci di luar tiga profil (UNSUPPORTED_ALGORITHM).
  static Outcome<PrivateKey> from_evp(EvpPkey pkey);

  Algorithm algorithm() const noexcept { return algorithm_; }
  EVP_PKEY* get() const noexcept { return pkey_.get(); }

 private:
  PrivateKey(EvpPkey pkey, Algorithm a) : pkey_(std::move(pkey)), algorithm_(a) {}
  EvpPkey pkey_;
  Algorithm algorithm_;
};

class PublicKey {
 public:
  static Outcome<PublicKey> from_evp(EvpPkey pkey);

  Algorithm algorithm() const noexcept { return algorithm_; }
  EVP_PKEY* get() const noexcept { return pkey_.get(); }

 private:
  PublicKey(EvpPkey pkey, Algorithm a) : pkey_(std::move(pkey)), algorithm_(a) {}
  EvpPkey pkey_;
  Algorithm algorithm_;
};

}  // namespace sister_sign::crypto
