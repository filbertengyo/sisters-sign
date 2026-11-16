#pragma once
/// @file
/// @brief Versi program.
#include <string_view>

namespace sister_sign::util {
/// @brief Versi program, mis. `"0.1.0"`.
///
/// Sama dengan output `sister-sign -version` tanpa awalan `sister-sign `. Nilainya ditulis di
/// version.cpp dan harus sama dengan `project(... VERSION ...)` di CMakeLists.txt serta tag rilis
/// (dicek `ci/release-check.sh`).
std::string_view version();
}  // namespace sister_sign::util
