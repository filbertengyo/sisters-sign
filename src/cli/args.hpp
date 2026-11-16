#pragma once
/// @file
/// @brief Parser flag gaya `-nama nilai` / `-nama=nilai` (juga `--nama`). Tanpa prompt dan tanpa
/// stdin.
///
/// Aturan: flag tidak dikenal, nilai hilang, flag ganda, argumen posisional liar, dan flag wajib
/// yang hilang semuanya INPUT_ERROR (exit 2) dengan pesan yang menyebut nama flag-nya.
#include <map>
#include <set>
#include <span>
#include <string>
#include <string_view>

#include "util/result.hpp"

namespace sister_sign::cli {

/// @brief Deklarasi satu flag subcommand.
struct Flag {
  std::string_view name;  ///< tanpa tanda minus, mis. `"algorithm"`
  bool takes_value;       ///< false = flag boolean seperti `-force`
  bool required;          ///< true = wajib (hilang -> INPUT_ERROR)
  std::string_view help;  ///< teks bantuan di usage
};

/// @brief Hasil parse_flags().
class Parsed {
 public:
  bool help_requested() const { return help_; }
  bool has(std::string_view name) const { return present_.contains(std::string(name)); }
  /// @brief Nilai flag, atau string kosong bila tidak diberikan / flag boolean.
  std::string_view value(std::string_view name) const;

 private:
  friend Outcome<Parsed> parse_flags(std::span<const std::string_view> args,
                                     std::span<const Flag> flags);
  bool help_ = false;
  std::set<std::string> present_;
  std::map<std::string, std::string> values_;
};

/// @brief Parse argumen sebuah subcommand.
///
/// `-help` / `--help` di mana pun menghentikan parsing: help_requested() true, tanpa pemeriksaan
/// flag wajib.
/// @param args argumen setelah nama subcommand
/// @param flags flag yang dikenal
/// @return hasil parse, atau `INPUT_ERROR` (flag tidak dikenal, nilai hilang, flag ganda, argumen
///         posisional, flag wajib hilang)
Outcome<Parsed> parse_flags(std::span<const std::string_view> args, std::span<const Flag> flags);

/// @brief Teks usage satu subcommand.
std::string usage_text(std::string_view command, std::string_view summary,
                       std::span<const Flag> flags);

}  // namespace sister_sign::cli
