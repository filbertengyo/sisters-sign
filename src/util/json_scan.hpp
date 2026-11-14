#pragma once
// Scanner JSON mentah: memeriksa sintaks dan melaporkan key ganda per objek.
//
// Parser JSON biasa (termasuk glaze) umumnya membuang salah satu key ganda secara diam-diam.
// Scanner ini membaca byte aslinya, jadi dipakai manifest, bundle, dan trust store sebelum parse.
// Key dibandingkan setelah escape didekode ("a" dan "a" dianggap sama).
#include <string_view>

#include "util/result.hpp"

namespace sister_sign::util {

// Kedalaman bersarang maksimum yang diterima (cegah stack overflow dari input jahat).
inline constexpr int kJsonMaxDepth = 64;

// OK bila `json` satu nilai JSON yang sah (RFC 8259, tanpa sisa data) dan tidak ada objek dengan
// key ganda. Selain itu FORMAT_ERROR; pesan menyebut sebab dan offset, tidak pernah isi nilainya.
Outcome<void> check_json_no_duplicate_keys(std::string_view json);

}  // namespace sister_sign::util
