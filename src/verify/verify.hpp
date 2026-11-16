#pragma once
/// @file
/// @brief Verifikasi artefak (Algoritma 2).
#include <filesystem>
#include <string_view>

#include "util/result.hpp"

namespace sister_sign::verifier {

/// @brief Verifikasi artefak terhadap bundle dan trust store.
///
/// Urutan pemeriksaan TETAP dan berhenti di kegagalan pertama:
///
/// 1. `INPUT_ERROR`: artefak, bundle, atau trust store tidak ada/tidak terbaca (artefak harus
///    berkas biasa).
/// 2. `FORMAT_ERROR`: bundle, manifest (harus kanonik), atau trust store tidak lolos parse strict.
/// 3. `UNSUPPORTED_ALGORITHM`: nama algoritma di manifest di luar tiga profil.
/// 4. `KEY_NOT_TRUSTED`: keyid manifest tidak ada di trust store, profil kunci berbeda dari
///    manifest, atau kunci tidak diizinkan untuk package yang DIHARAPKAN PENGGUNA. Pubkey hanya
///    diambil dari trust store, tidak pernah dari bundle; tidak ada kunci lain yang dicoba.
/// 5. `INVALID_SIGNATURE`: signature tidak cocok dengan byte M persis seperti di bundle (panjang
///    atau nilai r/s yang tidak sah juga di sini).
/// 6. `METADATA_MISMATCH`: package/version manifest berbeda dari masukan pengguna, atau
///    artifact.name berbeda dari basename artefak.
/// 7. `ARTIFACT_MISMATCH`: ukuran lalu SHA-256 artefak berbeda dari manifest.
///
/// Sesuai Tabel 2.9, algorithm/keyid/package/version di Result diisi dari manifest begitu
/// manifest berhasil dibaca (setelah langkah 2); sebelum itu kosong (`null` di JSON). Pada
/// kegagalan, nilai itu hanya penjelasan dan bukan data yang sah.
///
/// @param file artefak yang diverifikasi
/// @param bundle_path berkas bundle
/// @param trust_store_path berkas trust store
/// @param package package yang diharapkan pengguna
/// @param version versi yang diharapkan pengguna
/// @return Result; `valid == true` hanya bila semua langkah lulus. Exit code: exit_code(status).
Result verify(const std::filesystem::path& file, const std::filesystem::path& bundle_path,
              const std::filesystem::path& trust_store_path, std::string_view package,
              std::string_view version);

}  // namespace sister_sign::verifier
