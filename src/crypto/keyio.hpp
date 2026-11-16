#pragma once
/// @file
/// @brief Key I/O: keygen, PEM baca/tulis, validasi profil, dan berkas kunci.
///
/// Format: privkey PKCS#8 PEM (label `PRIVATE KEY`, tanpa enkripsi), pubkey SPKI PEM (label
/// `PUBLIC KEY`). Profil yang diterima: RSA 3072/e=65537, ECDSA P-256 (named curve), Ed25519.
/// Profil algoritma diturunkan dari kunci. Isi privkey tidak pernah masuk ke pesan error.
#include <filesystem>
#include <string>
#include <string_view>

#include "crypto/keys.hpp"
#include "crypto/raii.hpp"

namespace sister_sign::crypto {

/// @brief Pasangan kunci hasil generate_keypair().
struct KeyPair {
  PrivateKey priv;  ///< privkey
  PublicKey pub;    ///< pubkey yang sesuai
};

// ---- keygen ------------------------------------------------------------------------------------

/// @brief Buat pasangan kunci baru untuk sebuah profil.
/// @param algorithm profil
/// @return pasangan kunci, atau `INPUT_ERROR` bila OpenSSL gagal
Outcome<KeyPair> generate_keypair(Algorithm algorithm);

/// @brief Turunkan pubkey dari privkey.
/// @param key privkey
/// @return pubkey, atau `INPUT_ERROR`
Outcome<PublicKey> public_key_of(const PrivateKey& key);

// ---- PEM ---------------------------------------------------------------------------------------

/// @brief Parse privkey PKCS#8 PEM.
///
/// Menolak label salah (termasuk `ENCRYPTED PRIVATE KEY` dan format tradisional), header PEM,
/// lebih dari satu blok atau sisa data, DER rusak, dan kunci di luar profil.
/// @param pem teks PEM
/// @return privkey, atau `FORMAT_ERROR` (PEM/DER rusak, label salah) atau
///         `UNSUPPORTED_ALGORITHM` (RSA 2048, P-384, Ed448, ...)
Outcome<PrivateKey> parse_private_key_pem(std::string_view pem);

/// @brief Parse pubkey SPKI PEM. Aturan penolakan sama dengan parse_private_key_pem().
/// @param pem teks PEM (label `PUBLIC KEY`)
/// @return pubkey, atau `FORMAT_ERROR` / `UNSUPPORTED_ALGORITHM`
Outcome<PublicKey> parse_public_key_pem(std::string_view pem);

/// @brief Serialisasi privkey ke PKCS#8 PEM.
/// @param key privkey
/// @return PEM dalam buffer yang dibersihkan dari memori saat dibebaskan, atau `INPUT_ERROR`
Outcome<SecureBuffer> private_key_to_pem(const PrivateKey& key);

/// @brief Serialisasi pubkey ke SPKI PEM.
/// @param key pubkey
/// @return PEM, atau `INPUT_ERROR`
Outcome<std::string> public_key_to_pem(const PublicKey& key);

// ---- berkas ------------------------------------------------------------------------------------

/// @brief Baca privkey PKCS#8 PEM dari berkas (maks. 64 KiB).
/// @param path path berkas
/// @return privkey; `INPUT_ERROR` bila berkas tidak ada/tidak terbaca, selain itu seperti
///         parse_private_key_pem()
Outcome<PrivateKey> read_private_key(const std::filesystem::path& path);

/// @brief Baca pubkey SPKI PEM dari berkas.
/// @param path path berkas
/// @return pubkey; `INPUT_ERROR` bila berkas tidak ada/tidak terbaca, selain itu seperti
///         parse_public_key_pem()
Outcome<PublicKey> read_public_key(const std::filesystem::path& path);

/// @brief Tulis privkey ke berkas dengan mode 0600.
/// @param path path berkas
/// @param key privkey
/// @param overwrite false: gagal (`INPUT_ERROR`) bila berkas sudah ada
/// @return kosong bila sukses, atau `INPUT_ERROR`
Outcome<void> write_private_key(const std::filesystem::path& path, const PrivateKey& key,
                                bool overwrite = false);

/// @brief Tulis pubkey ke berkas dengan mode 0644.
/// @param path path berkas
/// @param key pubkey
/// @param overwrite false: gagal (`INPUT_ERROR`) bila berkas sudah ada
/// @return kosong bila sukses, atau `INPUT_ERROR`
Outcome<void> write_public_key(const std::filesystem::path& path, const PublicKey& key,
                               bool overwrite = false);

}  // namespace sister_sign::crypto
