#pragma once
/// @file
/// @brief Kontrak bersama: status, hasil verify, dan tipe error untuk semua komponen.
#include <expected>
#include <string>
#include <string_view>
#include <utility>

namespace sister_sign {

/// @brief Status hasil operasi.
///
/// Urutan enum = prioritas pemeriksaan verify (berhenti di kegagalan pertama). String dan exit
/// code tiap nilai: lihat to_string() dan exit_code().
enum class Status {
  Ok,                    ///< `OK`, exit 0
  InputError,            ///< `INPUT_ERROR`, exit 2: berkas tidak ada/tidak terbaca, argumen salah
  FormatError,           ///< `FORMAT_ERROR`, exit 1: bundle/manifest/trust store tidak sah
  UnsupportedAlgorithm,  ///< `UNSUPPORTED_ALGORITHM`, exit 1: algoritma di luar tiga profil
  KeyNotTrusted,         ///< `KEY_NOT_TRUSTED`, exit 1: kunci tidak dipercaya untuk package
  InvalidSignature,      ///< `INVALID_SIGNATURE`, exit 1: signature tidak cocok dengan manifest
  MetadataMismatch,      ///< `METADATA_MISMATCH`, exit 1: package/version/nama berkas berbeda
  ArtifactMismatch,      ///< `ARTIFACT_MISMATCH`, exit 1: ukuran/SHA-256 artefak berbeda
};

/// @brief Nama status untuk output (`"OK"`, `"INPUT_ERROR"`, `"FORMAT_ERROR"`, ...).
/// @param s status
/// @return string statis, tidak perlu dibebaskan
std::string_view to_string(Status s);

/// @brief Exit code proses untuk sebuah status (Tabel 2.10).
///
/// Satu-satunya tempat pemetaan status -> exit code: `Ok` = 0, `InputError` = 2, penolakan lain
/// = 1.
/// @param s status
/// @return 0, 1, atau 2
int exit_code(Status s);

/// @brief Hasil akhir verify; dipakai juga untuk output `verify -json` (Tabel 2.9).
///
/// `algorithm`, `keyid`, `package`, `version` diisi dari manifest begitu manifest berhasil
/// dibaca; sebelum itu kosong (`null` di JSON).
struct Result {
  bool valid = false;          ///< true hanya bila `status == Status::Ok`
  Status status = Status::Ok;  ///< status pertama yang gagal, atau `Ok`
  std::string message;         ///< penjelasan untuk manusia (tidak memuat isi kunci)
  std::string algorithm;       ///< nama algoritma dari manifest, mis. `"ed25519"`
  std::string keyid;           ///< keyid dari manifest (64 hex huruf kecil)
  std::string package;         ///< package dari manifest
  std::string version;         ///< version dari manifest
};

/// @brief Result dengan `valid = true` dan `status = Status::Ok`.
Result ok_result();

/// @brief Result gagal dengan status dan pesan tertentu.
/// @param status status kegagalan (bukan `Ok`)
/// @param message penjelasan
Result fail(Status status, std::string message);

/// @brief Error untuk fungsi yang bisa gagal.
///
/// Tidak ada exception yang melewati batas modul: semua fungsi yang bisa gagal mengembalikan
/// Outcome.
struct Error {
  Status status;        ///< kategori kegagalan
  std::string message;  ///< penjelasan (tidak pernah memuat isi privkey)
};

/// @brief Nilai `T` atau Error.
///
/// Periksa dengan `if (!r)`, ambil nilai dengan `*r`, error dengan `r.error()`.
/// @tparam T tipe nilai saat sukses (`void` untuk operasi tanpa nilai)
template <class T>
using Outcome = std::expected<T, Error>;

/// @brief Pembantu untuk `return make_error(...)` di fungsi yang mengembalikan Outcome.
/// @param status kategori kegagalan
/// @param message penjelasan
inline std::unexpected<Error> make_error(Status status, std::string message) {
  return std::unexpected<Error>(Error{status, std::move(message)});
}

}  // namespace sister_sign
