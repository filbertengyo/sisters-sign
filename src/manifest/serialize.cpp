#include <string>

#include "manifest/manifest.hpp"

namespace sister_sign::manifest {
namespace {

Outcome<void> check(const Manifest& m) {
  auto bad = [](const char* field) -> Outcome<void> {
    return make_error(Status::FormatError,
                      std::string("manifest: field ") + field + " tidak valid");
  };
  if (!valid_package(m.package)) return bad("package");
  if (!valid_version(m.version)) return bad("version");
  if (!valid_algorithm_token(m.algorithm)) return bad("algorithm");
  if (!valid_hex64(m.keyid)) return bad("keyid");
  if (!valid_artifact_name(m.artifact.name)) return bad("artifact.name");
  if (m.artifact.size > kMaxSize) return bad("artifact.size");
  if (!valid_hex64(m.artifact.sha256)) return bad("artifact.sha256");
  return {};
}

}  // namespace

Outcome<std::string> serialize(const Manifest& m) {
  if (auto r = check(m); !r) return std::unexpected(r.error());

  // Semua string sudah dibatasi ke ASCII tanpa karakter yang perlu di-escape.
  std::string out;
  out.reserve(256);
  out += R"({"schema":")";
  out += kSchema;
  out += R"(","package":")";
  out += m.package;
  out += R"(","version":")";
  out += m.version;
  out += R"(","algorithm":")";
  out += m.algorithm;
  out += R"(","keyid":")";
  out += m.keyid;
  out += R"(","artifact":{"name":")";
  out += m.artifact.name;
  out += R"(","size":)";
  out += std::to_string(m.artifact.size);
  out += R"(,"sha256":")";
  out += m.artifact.sha256;
  out += R"("}})";

  if (out.size() > kMaxManifestBytes) {
    return make_error(Status::FormatError, "manifest melebihi 16 KiB");
  }
  return out;
}

}  // namespace sister_sign::manifest
