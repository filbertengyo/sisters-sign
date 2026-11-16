#pragma once
/// @file
/// @brief Tipe byte bersama.
#include <cstdint>
#include <span>
#include <vector>

namespace sister_sign {

/// @brief Buffer byte milik sendiri.
using Bytes = std::vector<std::uint8_t>;
/// @brief Tampilan byte read-only (tanpa salinan); bisa dibuat dari Bytes atau array.
using ByteView = std::span<const std::uint8_t>;

}  // namespace sister_sign
