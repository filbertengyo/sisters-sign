#pragma once
// Bundle: membungkus manifest (M) dan signature tanpa mengubah byte M.
//
// {"schema":"minisign-bundle/v1","manifest_b64":"...","signature_b64":"..."}
// UTF-8 tanpa BOM, maksimum 64 KiB. Urutan field dan whitespace bundle bebas; field tambahan dan
// key ganda ditolak. Base64 strict (RFC 4648). Isi M tidak di-parse di sini: byte dikembalikan
// apa adanya, dan signature diverifikasi atas byte tersebut.
#include <cstddef>
#include <string>
#include <string_view>

#include "util/bytes.hpp"
#include "util/result.hpp"

namespace sister_sign::bundle {

inline constexpr std::string_view kSchema = "minisign-bundle/v1";
inline constexpr std::size_t kMaxBundleBytes = 64 * 1024;

struct Bundle {
  Bytes manifest;   // byte M persis seperti yang ditandatangani
  Bytes signature;  // panjang/validitas diperiksa oleh verify
};

// Tulis bundle (satu baris, tanpa newline akhir). FORMAT_ERROR bila hasil > 64 KiB.
Outcome<std::string> write(const Bundle& b);

// Strict read. Semua penolakan = FORMAT_ERROR: sintaks, key ganda, field tambahan/kurang, tipe
// salah, schema salah, base64 tidak kanonik, > 64 KiB, BOM.
Outcome<Bundle> read(std::string_view json);

}  // namespace sister_sign::bundle
