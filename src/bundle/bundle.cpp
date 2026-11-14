#include "bundle/bundle.hpp"

#include <glaze/glaze.hpp>

#include "util/base64.hpp"
#include "util/json_scan.hpp"

namespace sister_sign::bundle {
namespace {

struct RawBundle {
  std::string schema;
  std::string manifest_b64;
  std::string signature_b64;
};

}  // namespace

Outcome<std::string> write(const Bundle& b) {
  // Base64 standar hanya berisi [A-Za-z0-9+/=], jadi tidak butuh escape JSON.
  std::string out;
  out += R"({"schema":")";
  out += kSchema;
  out += R"(","manifest_b64":")";
  out += util::base64_encode(b.manifest);
  out += R"(","signature_b64":")";
  out += util::base64_encode(b.signature);
  out += R"("})";
  if (out.size() > kMaxBundleBytes) {
    return make_error(Status::FormatError, "bundle melebihi 64 KiB");
  }
  return out;
}

Outcome<Bundle> read(std::string_view json) {
  if (json.size() > kMaxBundleBytes) {
    return make_error(Status::FormatError, "bundle melebihi 64 KiB");
  }
  if (json.starts_with("\xEF\xBB\xBF")) {
    return make_error(Status::FormatError, "bundle: BOM tidak diperbolehkan");
  }
  if (auto r = util::check_json_no_duplicate_keys(json); !r) return std::unexpected(r.error());

  RawBundle raw;
  constexpr glz::opts kOpts{.error_on_unknown_keys = true, .error_on_missing_keys = true};
  if (auto ec = glz::read<kOpts>(raw, json)) {
    return make_error(Status::FormatError, "bundle: struktur/tipe tidak sesuai skema");
  }
  if (raw.schema != kSchema) return make_error(Status::FormatError, "bundle: schema salah");

  auto m = util::base64_decode(raw.manifest_b64);
  if (!m) return make_error(Status::FormatError, "bundle: manifest_b64 bukan base64 strict");
  auto s = util::base64_decode(raw.signature_b64);
  if (!s) return make_error(Status::FormatError, "bundle: signature_b64 bukan base64 strict");
  return Bundle{std::move(*m), std::move(*s)};
}

}  // namespace sister_sign::bundle
