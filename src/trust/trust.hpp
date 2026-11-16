#pragma once
/// @file
/// @brief Trust store: daftar pubkey yang dipercaya beserta package yang boleh ditandatanganinya.
///
/// Berkas JSON `minisign-trust/v1`:
/// @code{.json}
/// {"schema":"minisign-trust/v1","keys":[{"keyid":"...","algorithm":"...","public_key_pem":"...","packages":["..."]}]}
/// @endcode
/// Store kosong = tidak percaya siapa pun. Satu-satunya jalur menambah trust adalah add() yang
/// dipanggil `trust add`; bundle tidak pernah menambah trust.
#include <cstddef>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "crypto/keyio.hpp"
#include "crypto/keys.hpp"
#include "util/result.hpp"

namespace sister_sign::trust {

/// @brief Nilai field `schema` trust store.
inline constexpr std::string_view kSchema = "minisign-trust/v1";
/// @brief Ukuran maksimum berkas trust store (byte).
inline constexpr std::size_t kMaxStoreBytes = 1024 * 1024;

/// @brief Satu kunci tepercaya.
struct Entry {
  std::string keyid;                  ///< keyid pubkey (64 hex)
  crypto::Algorithm algorithm;        ///< profil kunci
  std::string public_key_pem;         ///< pubkey SPKI PEM
  std::vector<std::string> packages;  ///< package yang diizinkan: non-empty, unik, tanpa wildcard
  crypto::PublicKey key;              ///< pubkey hasil parse public_key_pem
};

/// @brief Trust store di memori.
class TrustStore {
 public:
  /// @brief Store kosong (tidak percaya siapa pun).
  TrustStore() = default;

  /// @brief Strict parse + validasi.
  ///
  /// Semua pelanggaran = `FORMAT_ERROR`: sintaks, key ganda, field tambahan/kurang, tipe salah,
  /// schema, keyid ganda, packages kosong/ganda/wildcard/di luar pola, algoritma tak dikenal,
  /// pubkey tak sah atau di luar profil, algoritma/fingerprint tak cocok.
  /// @param json isi berkas
  /// @return store, atau `FORMAT_ERROR`
  static Outcome<TrustStore> parse(std::string_view json);

  /// @brief Baca store dari berkas.
  /// @param path path berkas
  /// @return store; `INPUT_ERROR` bila berkas tidak ada, `FORMAT_ERROR` bila isinya buruk
  static Outcome<TrustStore> load(const std::filesystem::path& path);
  /// @brief Seperti load(), tetapi berkas yang belum ada menghasilkan store kosong.
  /// @param path path berkas
  static Outcome<TrustStore> load_or_empty(const std::filesystem::path& path);

  /// @brief Cari pubkey untuk keyid yang diizinkan menandatangani package.
  /// @param keyid keyid dari manifest
  /// @param package package yang DIHARAPKAN pengguna (bukan dari manifest)
  /// @param algorithm profil yang tertulis di manifest
  /// @return pointer ke pubkey (berlaku selama store tidak diubah), atau `KEY_NOT_TRUSTED` bila
  ///         keyid tidak ada, package tidak terdaftar untuk keyid itu, atau profil berbeda
  Outcome<const crypto::PublicKey*> lookup(std::string_view keyid, std::string_view package,
                                           crypto::Algorithm algorithm) const;

  /// @brief Percayai pubkey untuk package. Idempoten.
  ///
  /// Keyid baru = entri baru; keyid sama = package ditambahkan ke entri lama.
  /// @param key pubkey
  /// @param package nama package
  /// @return kosong, atau `INPUT_ERROR` bila package di luar pola
  Outcome<void> add(const crypto::PublicKey& key, std::string_view package);

  /// @brief Hapus seluruh entri sebuah keyid.
  /// @param keyid keyid (64 hex)
  /// @return kosong, atau `INPUT_ERROR` bila keyid tidak ditemukan
  Outcome<void> remove(std::string_view keyid);

  /// @brief Semua entri.
  const std::vector<Entry>& entries() const { return entries_; }

  /// @brief JSON deterministik (entri urut keyid, package urut abjad, prettify, newline akhir).
  Outcome<std::string> to_json() const;

  /// @brief Tulis atomic: temp file di direktori yang sama -> fsync -> rename -> fsync direktori.
  ///
  /// Berkas lama tidak berubah bila ada langkah yang gagal.
  /// @param path path berkas
  /// @return kosong, atau `INPUT_ERROR`
  Outcome<void> save(const std::filesystem::path& path) const;

 private:
  std::vector<Entry> entries_;
};

}  // namespace sister_sign::trust
