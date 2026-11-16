#pragma once
/// @file
/// @brief Hex huruf kecil untuk keyid dan SHA-256.
#include <string>
#include <string_view>

#include "util/bytes.hpp"
#include "util/result.hpp"

namespace sister_sign::util {

/// @brief Encode hex huruf kecil, 2 karakter per byte.
/// @param bytes data mentah
/// @return teks hex, mis. `{0xab, 0x01}` -> `"ab01"`
std::string hex_lower(ByteView bytes);

/// @brief Decode hex strict: panjang genap dan hanya `[0-9a-f]` (huruf besar ditolak).
/// @param hex teks hex
/// @return byte hasil decode, atau `FORMAT_ERROR`
Outcome<Bytes> hex_decode(std::string_view hex);

}  // namespace sister_sign::util
