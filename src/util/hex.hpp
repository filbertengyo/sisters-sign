#pragma once
#include <string>
#include <string_view>

#include "util/bytes.hpp"
#include "util/result.hpp"

namespace sister_sign::util {

// Huruf kecil, 2 karakter per byte.
std::string hex_lower(ByteView bytes);

// Strict: panjang genap dan hanya [0-9a-f]. Selain itu FORMAT_ERROR.
Outcome<Bytes> hex_decode(std::string_view hex);

}  // namespace sister_sign::util
