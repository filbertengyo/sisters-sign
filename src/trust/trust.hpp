#pragma once
// Trust store: daftar pubkey yang dipercaya beserta package yang boleh ditandatanganinya.
//
// File JSON `minisign-trust/v1`:
//   {"schema":"minisign-trust/v1","keys":[{"keyid":...,"algorithm":...,"public_key_pem":...,
//    "packages":[...]}]}
// Store kosong = tidak percaya siapa pun. Satu-satunya jalur menambah trust adalah add() yang
// dipanggil `trust add`; bundle tidak pernah menambah trust.
#include <cstddef>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "crypto/keyio.hpp"
#include "crypto/keys.hpp"
#include "util/result.hpp"

namespace sister_sign::trust {

inline constexpr std::string_view kSchema = "minisign-trust/v1";
inline constexpr std::size_t kMaxStoreBytes = 1024 * 1024;

struct Entry {
  std::string keyid;
  crypto::Algorithm algorithm;
  std::string public_key_pem;
  std::vector<std::string> packages;  // non-empty, unik, tanpa wildcard
  crypto::PublicKey key;
};

class TrustStore {
 public:
  TrustStore() = default;  // kosong

  // Strict parse + validasi. Semua pelanggaran = FORMAT_ERROR: sintaks, key ganda, field
  // tambahan/kurang, tipe salah, schema, keyid ganda, packages kosong/ganda/wildcard/di luar pola,
  // algoritma tak dikenal, pubkey tak sah atau di luar profil, algoritma/fingerprint tak cocok.
  static Outcome<TrustStore> parse(std::string_view json);

  // Berkas tidak ada = INPUT_ERROR; isi buruk = FORMAT_ERROR.
  static Outcome<TrustStore> load(const std::filesystem::path& path);
  // Seperti load, tetapi berkas yang belum ada menghasilkan store kosong.
  static Outcome<TrustStore> load_or_empty(const std::filesystem::path& path);

  // KEY_NOT_TRUSTED bila keyid tidak ada, package tidak terdaftar untuk keyid itu, atau profil
  // algoritma berbeda dari yang tercatat. Pointer berlaku selama store tidak diubah.
  Outcome<const crypto::PublicKey*> lookup(std::string_view keyid, std::string_view package,
                                           crypto::Algorithm algorithm) const;

  // Idempoten. Keyid baru = entri baru; keyid sama = package ditambahkan ke entri lama.
  // INPUT_ERROR bila package di luar pola.
  Outcome<void> add(const crypto::PublicKey& key, std::string_view package);

  // Hapus seluruh entri. INPUT_ERROR bila keyid tidak ditemukan.
  Outcome<void> remove(std::string_view keyid);

  const std::vector<Entry>& entries() const { return entries_; }

  // JSON deterministik (entri urut keyid, package urut abjad, prettify glaze, newline akhir).
  Outcome<std::string> to_json() const;

  // Tulis atomic: temp file di direktori yang sama -> fsync -> rename -> fsync direktori.
  // Berkas lama tidak berubah bila ada langkah yang gagal. Kegagalan I/O = INPUT_ERROR.
  Outcome<void> save(const std::filesystem::path& path) const;

 private:
  std::vector<Entry> entries_;
};

}  // namespace sister_sign::trust
