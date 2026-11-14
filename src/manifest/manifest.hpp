#pragma once
// Manifest: metadata artefak yang ditandatangani. Yang ditandatangani adalah BYTE manifest (M),
// jadi satu manifest hanya punya satu representasi byte (kanonik) dan hanya bentuk kanonik yang
// lolos parse.
//
// Bentuk kanonik: {"schema":...,"package":...,"version":...,"algorithm":...,"keyid":...,
// "artifact":{"name":...,"size":...,"sha256":...}} tanpa spasi/newline, UTF-8 tanpa BOM, string
// ASCII tanpa escape, angka desimal polos, maksimum 16 KiB.
//
// ASUMSI (cocokkan dengan spek, ubah hanya di sini dan validators.cpp): nilai schema, nama
// algoritma, dan pola package/version/artifact.name.
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "crypto/crypto.hpp"
#include "util/result.hpp"

namespace sister_sign::manifest {

inline constexpr std::string_view kSchema = "minisign-manifest/v1";
inline constexpr std::size_t kMaxManifestBytes = 16 * 1024;
inline constexpr std::uint64_t kMaxSize = (std::uint64_t{1} << 53) - 1;

struct ArtifactInfo {
  std::string name;
  std::uint64_t size = 0;
  std::string sha256;  // 64 hex huruf kecil
};

struct Manifest {
  std::string package;
  std::string version;
  std::string algorithm;  // string di manifest; tak dikenal -> ditolak verify (bukan parse)
  std::string keyid;      // 64 hex huruf kecil
  ArtifactInfo artifact;
};

// ---- validator field ---------------------------------------------------------------------------
// package : ^[a-z0-9][a-z0-9._-]{0,63}$
// version : ^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$
// name    : ^[A-Za-z0-9._-]{1,255}$, bukan "." atau ".."
// algorithm (token, bukan daftar profil): ^[a-z0-9][a-z0-9._-]{0,63}$
bool valid_package(std::string_view s);
bool valid_version(std::string_view s);
bool valid_artifact_name(std::string_view s);
bool valid_algorithm_token(std::string_view s);
bool valid_hex64(std::string_view s);  // keyid dan sha256

// ---- nama algoritma ----------------------------------------------------------------------------
std::string_view algorithm_name(crypto::Algorithm a);  // "rsa-pss" / "ecdsa-p256" / "ed25519"
bool parse_algorithm_name(std::string_view s, crypto::Algorithm& out);  // false bila tak dikenal

// ---- serialize / parse -------------------------------------------------------------------------
// Serialize kanonik. FORMAT_ERROR bila ada field di luar pola, size > 2^53-1, atau hasil > 16 KiB.
Outcome<std::string> serialize(const Manifest& m);

// Strict parse. Semua penolakan = FORMAT_ERROR: key ganda, field tambahan/kurang, null, tipe
// salah, urutan/whitespace tidak kanonik, regex gagal, schema salah, > 16 KiB.
// Parse -> serialize ulang -> bandingkan byte; beda berarti ditolak.
Outcome<Manifest> parse(std::string_view bytes);

}  // namespace sister_sign::manifest
