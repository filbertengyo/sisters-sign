#pragma once
/// @file
/// @brief Manifest: metadata artefak yang ditandatangani (Tabel 2.1 dan 2.3 spek).
///
/// Yang ditandatangani adalah BYTE manifest (M), jadi satu manifest hanya punya satu representasi
/// byte (kanonik) dan hanya bentuk kanonik yang lolos parse.
///
/// Bentuk kanonik:
/// @code{.json}
/// {"schema":"minisign-manifest/v1","package":...,"version":...,"algorithm":...,"keyid":...,"artifact":{"name":...,"size":...,"sha256":...}}
/// @endcode
/// tanpa spasi/newline, UTF-8 tanpa BOM, string ASCII tanpa escape, angka desimal polos, maksimum
/// 16 KiB.
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "crypto/crypto.hpp"
#include "util/result.hpp"

namespace sister_sign::manifest {

/// @brief Nilai field `schema` manifest.
inline constexpr std::string_view kSchema = "minisign-manifest/v1";
/// @brief Ukuran maksimum manifest (byte).
inline constexpr std::size_t kMaxManifestBytes = 16 * 1024;
/// @brief Nilai maksimum `artifact.size` (2^53 - 1, aman sebagai angka JSON).
inline constexpr std::uint64_t kMaxSize = (std::uint64_t{1} << 53) - 1;

/// @brief Objek `artifact` di manifest.
struct ArtifactInfo {
  std::string name;        ///< basename berkas artefak, pola valid_artifact_name()
  std::uint64_t size = 0;  ///< ukuran artefak (byte), maks. kMaxSize
  std::string sha256;      ///< SHA-256 artefak, 64 hex huruf kecil
};

/// @brief Isi manifest (tanpa `schema`, yang selalu kSchema).
struct Manifest {
  std::string package;    ///< nama package, pola valid_package()
  std::string version;    ///< versi, pola valid_version()
  std::string algorithm;  ///< nama algoritma; tak dikenal -> ditolak verify (bukan parse)
  std::string keyid;      ///< keyid penanda tangan, 64 hex huruf kecil
  ArtifactInfo artifact;  ///< artefak yang ditandatangani
};

// ---- validator field ---------------------------------------------------------------------------

/// @brief Pola package: `^[a-z0-9][a-z0-9._-]{0,63}$`.
bool valid_package(std::string_view s);
/// @brief Pola version: `^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`.
bool valid_version(std::string_view s);
/// @brief Pola artifact.name: `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`.
bool valid_artifact_name(std::string_view s);
/// @brief Token algoritma: ASCII tercetak tanpa `"` dan `\`, maks. 128 karakter.
///
/// Spek tidak membatasi pola; nilai tak dikenal menjadi `UNSUPPORTED_ALGORITHM` di verify.
bool valid_algorithm_token(std::string_view s);
/// @brief Tepat 64 hex huruf kecil (keyid dan sha256).
bool valid_hex64(std::string_view s);

// ---- nama algoritma ----------------------------------------------------------------------------

/// @brief Nama algoritma di manifest dan flag `-algorithm`.
/// @param a profil
/// @return `"rsa-pss-sha256"`, `"ecdsa-p256-sha256"`, atau `"ed25519"`
std::string_view algorithm_name(crypto::Algorithm a);
/// @brief Kebalikan algorithm_name().
/// @param s nama algoritma
/// @param[out] out profil, diisi bila dikenal
/// @return false bila nama tidak dikenal
bool parse_algorithm_name(std::string_view s, crypto::Algorithm& out);

// ---- serialize / parse -------------------------------------------------------------------------

/// @brief Serialisasi kanonik (byte M yang ditandatangani).
/// @param m isi manifest
/// @return byte kanonik, atau `FORMAT_ERROR` bila ada field di luar pola, size > kMaxSize, atau
///         hasil > 16 KiB
Outcome<std::string> serialize(const Manifest& m);

/// @brief Strict parse: parse -> serialize ulang -> bandingkan byte; beda berarti ditolak.
///
/// Semua penolakan = `FORMAT_ERROR`: key ganda, field tambahan/kurang, null, tipe salah,
/// urutan/whitespace tidak kanonik, regex gagal, schema salah, > 16 KiB.
/// @param bytes byte manifest (dari bundle::Bundle::manifest)
/// @return isi manifest, atau `FORMAT_ERROR`
Outcome<Manifest> parse(std::string_view bytes);

}  // namespace sister_sign::manifest
