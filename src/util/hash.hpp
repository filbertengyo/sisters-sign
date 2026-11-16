#pragma once
/// @file
/// @brief SHA-256 (OpenSSL EVP) satu kali jalan dan streaming.
#include <array>
#include <cstdint>
#include <memory>

#include "util/bytes.hpp"
#include "util/result.hpp"

namespace sister_sign::util {

/// @brief Digest SHA-256 (32 byte). Ubah ke teks dengan hex_lower().
using Sha256Digest = std::array<std::uint8_t, 32>;

/// @brief SHA-256 dari data di memori.
/// @param data data yang di-hash
/// @return digest, atau `INPUT_ERROR` bila OpenSSL gagal
Outcome<Sha256Digest> sha256(ByteView data);

/// @brief SHA-256 streaming untuk berkas besar: update() berkali-kali lalu finish() sekali.
///
/// Hanya bisa dipindah (move), tidak bisa disalin.
class Sha256 {
 public:
  Sha256();
  ~Sha256();
  Sha256(Sha256&&) noexcept;
  Sha256& operator=(Sha256&&) noexcept;
  Sha256(const Sha256&) = delete;
  Sha256& operator=(const Sha256&) = delete;

  /// @brief Tambahkan potongan data berikutnya.
  /// @param data potongan data
  /// @return kosong bila sukses, atau `INPUT_ERROR`
  Outcome<void> update(ByteView data);
  /// @brief Selesaikan dan ambil digest. Objek tidak boleh dipakai lagi setelahnya.
  /// @return digest seluruh data yang sudah di-update(), atau `INPUT_ERROR`
  Outcome<Sha256Digest> finish();

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace sister_sign::util
