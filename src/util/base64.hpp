#pragma once
/// @file
/// @brief Base64 strict (RFC 4648 bagian 4) untuk field `manifest_b64` dan `signature_b64` bundle.
#include <string>
#include <string_view>

#include "util/bytes.hpp"
#include "util/result.hpp"

namespace sister_sign::util {

/// @brief Encode base64 alfabet standar, dengan padding.
/// @param bytes data mentah
/// @return teks base64, mis. `{0x68, 0x69}` -> `"aGk="`
std::string base64_encode(ByteView bytes);

/// @brief Decode base64; hanya representasi kanonik yang diterima.
///
/// Menolak whitespace, alfabet salah (termasuk url-safe), padding salah/hilang, dan trailing bits
/// tidak nol. Jadi untuk setiap teks yang diterima, `base64_encode(*base64_decode(t)) == t`.
/// @param text teks base64
/// @return byte hasil decode, atau `FORMAT_ERROR`
Outcome<Bytes> base64_decode(std::string_view text);

}  // namespace sister_sign::util
