#pragma once
/// @file
/// @brief Scanner JSON mentah: memeriksa sintaks dan melaporkan key ganda per objek.
///
/// Parser JSON biasa (termasuk glaze) umumnya membuang salah satu key ganda secara diam-diam.
/// Scanner ini membaca byte aslinya, jadi dipakai manifest, bundle, dan trust store sebelum parse.
/// Key dibandingkan setelah escape didekode (`"a"` dan `"a"` dianggap sama).
#include <string_view>

#include "util/result.hpp"

namespace sister_sign::util {

/// @brief Kedalaman bersarang maksimum yang diterima (cegah stack overflow dari input jahat).
inline constexpr int kJsonMaxDepth = 64;

/// @brief Periksa bahwa teks adalah satu nilai JSON sah tanpa key ganda.
/// @param json teks JSON (RFC 8259, tanpa sisa data setelah nilai)
/// @return kosong bila sah, atau `FORMAT_ERROR`; pesan menyebut sebab dan offset, tidak pernah
///         isi nilainya
Outcome<void> check_json_no_duplicate_keys(std::string_view json);

}  // namespace sister_sign::util
