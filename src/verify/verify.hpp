#pragma once
// Verifikasi artefak (Algoritma 2). Urutan pemeriksaan TETAP dan berhenti di kegagalan pertama:
//
//   INPUT_ERROR -> FORMAT_ERROR -> UNSUPPORTED_ALGORITHM -> KEY_NOT_TRUSTED -> INVALID_SIGNATURE
//   -> METADATA_MISMATCH -> ARTIFACT_MISMATCH -> OK
//
//  1. INPUT_ERROR: artefak, bundle, atau trust store tidak ada/tidak terbaca (artefak harus berkas
//     biasa).
//  2. FORMAT_ERROR: bundle, manifest (harus kanonik), atau trust store tidak lolos parse strict.
//  3. UNSUPPORTED_ALGORITHM: nama algoritma di manifest di luar tiga profil.
//  4. KEY_NOT_TRUSTED: keyid manifest tidak ada di trust store untuk package dan profil itu. Pubkey
//     hanya diambil dari trust store, tidak pernah dari bundle; tidak ada kunci lain yang dicoba.
//  5. INVALID_SIGNATURE: signature tidak cocok dengan byte M persis seperti di bundle.
//  6. METADATA_MISMATCH: package/version manifest berbeda dari masukan pengguna, atau
//     artifact.name berbeda dari basename artefak.
//  7. ARTIFACT_MISMATCH: ukuran lalu SHA-256 artefak berbeda dari manifest.
//
// Hanya hasil yang sudah terotentikasi (OK, METADATA_MISMATCH, ARTIFACT_MISMATCH: signature sudah
// lolos) yang mengisi algorithm/keyid/package/version di Result; pada kegagalan sebelumnya isi
// manifest belum bisa dipercaya sehingga tidak dilaporkan.
#include <filesystem>
#include <string_view>

#include "util/result.hpp"

namespace sister_sign::verifier {

Result verify(const std::filesystem::path& file, const std::filesystem::path& bundle_path,
              const std::filesystem::path& trust_store_path, std::string_view package,
              std::string_view version);

}  // namespace sister_sign::verifier
