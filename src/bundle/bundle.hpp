#pragma once
/// @file
/// @brief Bundle: membungkus manifest (M) dan signature tanpa mengubah byte M.
///
/// @code{.json}
/// {"schema":"minisign-bundle/v1","manifest_b64":"...","signature_b64":"..."}
/// @endcode
/// UTF-8 tanpa BOM, maksimum 64 KiB. Urutan field dan whitespace bundle bebas; field tambahan dan
/// key ganda ditolak. Base64 strict (RFC 4648). Isi M tidak di-parse di sini: byte dikembalikan
/// apa adanya, dan signature diverifikasi atas byte tersebut.
#include <cstddef>
#include <string>
#include <string_view>

#include "util/bytes.hpp"
#include "util/result.hpp"

namespace sister_sign::bundle {

/// @brief Nilai field `schema` bundle.
inline constexpr std::string_view kSchema = "minisign-bundle/v1";
/// @brief Ukuran maksimum bundle (byte).
inline constexpr std::size_t kMaxBundleBytes = 64 * 1024;

/// @brief Isi bundle setelah base64 didekode.
struct Bundle {
  Bytes manifest;   ///< byte M persis seperti yang ditandatangani
  Bytes signature;  ///< signature; panjang/validitas diperiksa oleh verify
};

/// @brief Tulis bundle sebagai JSON satu baris, tanpa newline akhir.
/// @param b manifest + signature
/// @return teks JSON, atau `FORMAT_ERROR` bila hasil > 64 KiB
Outcome<std::string> write(const Bundle& b);

/// @brief Strict read.
///
/// Semua penolakan = `FORMAT_ERROR`: sintaks, key ganda, field tambahan/kurang, tipe salah,
/// schema salah, base64 tidak kanonik, > 64 KiB, BOM.
/// @param json isi berkas bundle
/// @return manifest + signature, atau `FORMAT_ERROR`
Outcome<Bundle> read(std::string_view json);

}  // namespace sister_sign::bundle
