#pragma once
#include <string>
#include <string_view>

#include "util/bytes.hpp"
#include "util/result.hpp"

namespace sister_sign::util {

// RFC 4648 section 4 (alfabet standar, dengan padding).
std::string base64_encode(ByteView bytes);

// Strict: hanya representasi kanonik yang diterima. Menolak whitespace, alfabet salah (termasuk
// url-safe), padding salah/hilang, dan trailing bits tidak nol. Selain itu FORMAT_ERROR.
Outcome<Bytes> base64_decode(std::string_view text);

}  // namespace sister_sign::util
