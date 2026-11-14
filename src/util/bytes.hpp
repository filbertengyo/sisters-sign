#pragma once
#include <cstdint>
#include <span>
#include <vector>

namespace sister_sign {

using Bytes = std::vector<std::uint8_t>;
using ByteView = std::span<const std::uint8_t>;

}  // namespace sister_sign
