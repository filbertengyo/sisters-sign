#pragma once
// Key I/O: keygen, PEM baca/tulis, validasi profil, dan berkas kunci.
//
// Format: privkey PKCS#8 PEM (label "PRIVATE KEY", tanpa enkripsi), pubkey SPKI PEM (label
// "PUBLIC KEY"). Profil yang diterima: RSA 3072/e=65537, ECDSA P-256 (named curve), Ed25519.
// Profil algoritma diturunkan dari kunci. Isi privkey tidak pernah masuk ke pesan error.
#include <filesystem>
#include <string>
#include <string_view>

#include "crypto/keys.hpp"
#include "crypto/raii.hpp"

namespace sister_sign::crypto {

struct KeyPair {
  PrivateKey priv;
  PublicKey pub;
};

// ---- keygen ------------------------------------------------------------------------------------
Outcome<KeyPair> generate_keypair(Algorithm algorithm);
Outcome<PublicKey> public_key_of(const PrivateKey& key);

// ---- PEM ---------------------------------------------------------------------------------------
// Tolak: label salah (termasuk "ENCRYPTED PRIVATE KEY" dan format tradisional), header PEM,
// lebih dari satu blok atau sisa data, DER rusak, dan kunci di luar profil.
//  - FORMAT_ERROR            : PEM/DER rusak, label salah
//  - UNSUPPORTED_ALGORITHM   : tipe/parameter di luar profil (RSA 2048, P-384, Ed448, ...)
Outcome<PrivateKey> parse_private_key_pem(std::string_view pem);
Outcome<PublicKey> parse_public_key_pem(std::string_view pem);

// Hasil privkey dibersihkan dari memori saat dibebaskan.
Outcome<SecureBuffer> private_key_to_pem(const PrivateKey& key);
Outcome<std::string> public_key_to_pem(const PublicKey& key);

// ---- berkas ------------------------------------------------------------------------------------
// Kegagalan I/O (tidak ada, tidak terbaca, sudah ada) = INPUT_ERROR.
Outcome<PrivateKey> read_private_key(const std::filesystem::path& path);
Outcome<PublicKey> read_public_key(const std::filesystem::path& path);

// overwrite=false: gagal bila berkas sudah ada. Privkey ditulis dengan mode 0600 (publik 0644).
Outcome<void> write_private_key(const std::filesystem::path& path, const PrivateKey& key,
                                bool overwrite = false);
Outcome<void> write_public_key(const std::filesystem::path& path, const PublicKey& key,
                               bool overwrite = false);

}  // namespace sister_sign::crypto
