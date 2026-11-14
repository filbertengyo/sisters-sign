#include "manifest/manifest.hpp"

namespace sister_sign::manifest {
namespace {

constexpr bool is_lower(char c) { return c >= 'a' && c <= 'z'; }
constexpr bool is_upper(char c) { return c >= 'A' && c <= 'Z'; }
constexpr bool is_digit(char c) { return c >= '0' && c <= '9'; }

}  // namespace

bool valid_package(std::string_view s) {
  if (s.empty() || s.size() > 64) return false;
  if (!(is_lower(s[0]) || is_digit(s[0]))) return false;
  for (char c : s) {
    if (!(is_lower(c) || is_digit(c) || c == '.' || c == '_' || c == '-')) return false;
  }
  return true;
}

bool valid_version(std::string_view s) {
  if (s.empty() || s.size() > 64) return false;
  if (!(is_lower(s[0]) || is_upper(s[0]) || is_digit(s[0]))) return false;
  for (char c : s) {
    if (!(is_lower(c) || is_upper(c) || is_digit(c) || c == '.' || c == '_' || c == '+' ||
          c == '-')) {
      return false;
    }
  }
  return true;
}

bool valid_artifact_name(std::string_view s) {
  if (s.empty() || s.size() > 128) return false;
  if (!(is_lower(s[0]) || is_upper(s[0]) || is_digit(s[0]))) return false;
  for (char c : s) {
    if (!(is_lower(c) || is_upper(c) || is_digit(c) || c == '.' || c == '_' || c == '-')) {
      return false;
    }
  }
  return true;
}

bool valid_algorithm_token(std::string_view s) {
  // Spek tidak membatasi pola nilai algorithm; nilai tak dikenal harus sampai ke pemeriksaan
  // UNSUPPORTED_ALGORITHM. Cukup ASCII tercetak yang tidak butuh escape JSON.
  if (s.size() > 128) return false;
  for (char c : s) {
    if (c < 0x20 || c > 0x7E || c == '"' || c == '\\') return false;
  }
  return true;
}

bool valid_hex64(std::string_view s) {
  if (s.size() != 64) return false;
  for (char c : s) {
    if (!(is_digit(c) || (c >= 'a' && c <= 'f'))) return false;
  }
  return true;
}

std::string_view algorithm_name(crypto::Algorithm a) {
  switch (a) {
    case crypto::Algorithm::RsaPss:
      return "rsa-pss-sha256";
    case crypto::Algorithm::EcdsaP256:
      return "ecdsa-p256-sha256";
    case crypto::Algorithm::Ed25519:
      return "ed25519";
  }
  return "";
}

bool parse_algorithm_name(std::string_view s, crypto::Algorithm& out) {
  for (auto a :
       {crypto::Algorithm::RsaPss, crypto::Algorithm::EcdsaP256, crypto::Algorithm::Ed25519}) {
    if (s == algorithm_name(a)) {
      out = a;
      return true;
    }
  }
  return false;
}

}  // namespace sister_sign::manifest
