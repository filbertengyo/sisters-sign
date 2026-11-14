#include <glaze/glaze.hpp>
#include <string>

#include "manifest/manifest.hpp"
#include "util/json_scan.hpp"

namespace sister_sign::manifest {
namespace {

// Bentuk mentah hasil glaze; dipindahkan ke Manifest setelah divalidasi.
struct RawArtifact {
  std::string name;
  std::uint64_t size = 0;
  std::string sha256;
};

struct RawManifest {
  std::string schema;
  std::string package;
  std::string version;
  std::string algorithm;
  std::string keyid;
  RawArtifact artifact;
};

Error format_error(std::string msg) { return Error{Status::FormatError, std::move(msg)}; }

}  // namespace

Outcome<Manifest> parse(std::string_view bytes) {
  if (bytes.size() > kMaxManifestBytes) {
    return make_error(Status::FormatError, "manifest melebihi 16 KiB");
  }

  // 1. Sintaks + key ganda dari byte mentah (glaze tidak melaporkan duplikat).
  if (auto r = util::check_json_no_duplicate_keys(bytes); !r) return std::unexpected(r.error());

  // 2. Isi: field tambahan/kurang, tipe salah, null, size bukan integer -> galat glaze.
  RawManifest raw;
  constexpr glz::opts kOpts{.error_on_unknown_keys = true, .error_on_missing_keys = true};
  if (auto ec = glz::read<kOpts>(raw, bytes)) {
    return make_error(Status::FormatError, "manifest: struktur/tipe tidak sesuai skema");
  }

  // 3. Nilai.
  if (raw.schema != kSchema) return make_error(Status::FormatError, "manifest: schema salah");
  Manifest m;
  m.package = std::move(raw.package);
  m.version = std::move(raw.version);
  m.algorithm = std::move(raw.algorithm);
  m.keyid = std::move(raw.keyid);
  m.artifact =
      ArtifactInfo{std::move(raw.artifact.name), raw.artifact.size, std::move(raw.artifact.sha256)};

  // serialize() memvalidasi semua field (regex, hex, ukuran).
  auto canonical = serialize(m);
  if (!canonical) return std::unexpected(format_error(canonical.error().message));

  // 4. Bentuk kanonik: byte harus identik dengan masukan.
  if (*canonical != bytes) {
    return make_error(Status::FormatError, "manifest: bukan bentuk kanonik");
  }
  return m;
}

}  // namespace sister_sign::manifest
