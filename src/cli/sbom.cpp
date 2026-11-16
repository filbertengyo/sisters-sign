// sbom (bonus): SBOM bertanda tangan yang terikat ke hash artefak rilis.
//
//   sister-sign sbom sign   -sbom S -package P -version V -key K -out B
//   sister-sign sbom verify -sbom S -bundle B -trust-store T -package P -version V [-json]
//   sister-sign sbom check  -sbom S -file F [-json]
//
// SBOM = CycloneDX JSON. Yang dibaca: bomFormat == "CycloneDX", specVersion, dan
// metadata.component {name, version, hashes[]} dengan SHA-256 (64 hex) artefak rilis. Field lain
// bebas (generator SBOM menambah banyak field), tetapi key ganda di mana pun ditolak dan dua
// SHA-256 yang berbeda dianggap ambigu.
//
//  sign   : SBOM harus sah dan metadata.component.name/version == -package/-version (exit 2 bila
//           tidak), lalu berkas SBOM ditandatangani seperti artefak biasa: bundle format yang sama,
//           manifest berisi nama, ukuran, dan SHA-256 berkas SBOM.
//  verify : Algoritma 2 atas berkas SBOM (persis `verify`), lalu isi SBOM: FORMAT_ERROR bila tidak
//           sah, METADATA_MISMATCH bila component.name/version != -package/-version.
//  check  : keterikatan SBOM <-> artefak: SHA-256(F) harus sama dengan SHA-256 di SBOM
//           (ARTIFACT_MISMATCH bila beda). Tidak memeriksa tanda tangan: jalankan `sbom verify`
//           dulu.
// Subperintah wajib (keygen, sign, verify, trust) tidak berubah.
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <glaze/glaze.hpp>
#include <optional>
#include <ostream>
#include <string>
#include <vector>

#include "cli/cli.hpp"
#include "manifest/manifest.hpp"
#include "util/hash.hpp"
#include "util/hex.hpp"
#include "util/json_scan.hpp"
#include "util/result.hpp"
#include "verify/verify.hpp"

namespace sister_sign::cli {
namespace {

namespace fs = std::filesystem;

constexpr std::size_t kMaxSbomBytes = 4 * 1024 * 1024;

constexpr std::string_view kUsage =
    "usage: sister-sign sbom <sign|verify|check> [options]\n"
    "Signed SBOM (CycloneDX) bound to the release artifact hash.\n"
    "  sign    validate an SBOM and sign it (same bundle format as `sign`)\n"
    "  verify  verify an SBOM signature (Algorithm 2) and its content\n"
    "  check   check that an artifact matches the SHA-256 recorded in the SBOM\n"
    "run 'sister-sign sbom <action> -help' for action options\n";

// Subset CycloneDX yang dibutuhkan; field lain diabaikan saat parse.
struct CdxHash {
  std::string alg;
  std::string content;
};
struct CdxComponent {
  std::string name;
  std::string version;
  std::vector<CdxHash> hashes;
};
struct CdxMetadata {
  std::optional<CdxComponent> component;
};
struct CdxBom {
  std::string bomFormat;
  std::string specVersion;
  std::optional<CdxMetadata> metadata;
};

struct SbomInfo {
  std::string name;
  std::string version;
  std::string sha256;  // hex huruf kecil
};

Outcome<SbomInfo> parse_sbom(std::string_view json) {
  if (json.size() > kMaxSbomBytes) return make_error(Status::FormatError, "SBOM melebihi 4 MiB");
  if (json.starts_with("\xEF\xBB\xBF")) {
    return make_error(Status::FormatError, "SBOM: BOM tidak diperbolehkan");
  }
  if (auto r = util::check_json_no_duplicate_keys(json); !r) {
    return make_error(Status::FormatError, "SBOM: " + r.error().message);
  }
  CdxBom bom;
  constexpr glz::opts kOpts{.error_on_unknown_keys = false, .error_on_missing_keys = false};
  if (auto ec = glz::read<kOpts>(bom, json)) {
    return make_error(Status::FormatError, "SBOM: struktur/tipe tidak sesuai CycloneDX");
  }
  if (bom.bomFormat != "CycloneDX" || bom.specVersion.empty()) {
    return make_error(Status::FormatError, "SBOM: bukan CycloneDX (bomFormat/specVersion)");
  }
  if (!bom.metadata || !bom.metadata->component) {
    return make_error(Status::FormatError, "SBOM: metadata.component tidak ada");
  }
  const CdxComponent& c = *bom.metadata->component;
  if (c.name.empty() || c.version.empty()) {
    return make_error(Status::FormatError, "SBOM: metadata.component.name/version kosong");
  }
  std::optional<std::string> sha;
  for (const auto& h : c.hashes) {
    if (h.alg != "SHA-256") continue;
    std::string v = h.content;
    for (auto& ch : v) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    if (!manifest::valid_hex64(v)) {
      return make_error(Status::FormatError, "SBOM: hash SHA-256 artefak bukan 64 hex");
    }
    if (sha && *sha != v) {
      return make_error(Status::FormatError, "SBOM: lebih dari satu SHA-256 artefak yang berbeda");
    }
    sha = v;
  }
  if (!sha) {
    return make_error(Status::FormatError,
                      "SBOM: metadata.component.hashes tidak memuat SHA-256 artefak rilis");
  }
  return SbomInfo{c.name, c.version, *sha};
}

Outcome<std::string> read_file_capped(const fs::path& path, std::size_t cap, const char* what) {
  std::error_code ec;
  if (!fs::is_regular_file(path, ec)) {
    return make_error(Status::InputError,
                      std::string(what) + " tidak ada atau bukan berkas biasa: " + path.string());
  }
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return make_error(Status::InputError,
                      std::string(what) + " tidak bisa dibuka: " + path.string());
  }
  std::string data(cap + 1, '\0');
  in.read(data.data(), static_cast<std::streamsize>(data.size()));
  if (in.bad()) {
    return make_error(Status::InputError, std::string(what) + " gagal dibaca: " + path.string());
  }
  data.resize(static_cast<std::size_t>(in.gcount()));
  return data;
}

Outcome<std::string> sha256_file(const fs::path& path) {
  std::error_code ec;
  if (!fs::is_regular_file(path, ec)) {
    return make_error(Status::InputError,
                      "artefak tidak ada atau bukan berkas biasa: " + path.string());
  }
  std::ifstream in(path, std::ios::binary);
  if (!in) return make_error(Status::InputError, "artefak tidak bisa dibuka: " + path.string());
  util::Sha256 hasher;
  Bytes buf(64 * 1024);
  while (true) {
    in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
    const auto n = static_cast<std::size_t>(in.gcount());
    if (n > 0) {
      if (auto r = hasher.update(ByteView(buf.data(), n)); !r) return std::unexpected(r.error());
    }
    if (in.eof()) break;
    if (!in) return make_error(Status::InputError, "artefak gagal dibaca: " + path.string());
  }
  auto d = hasher.finish();
  if (!d) return std::unexpected(d.error());
  return util::hex_lower(*d);
}

// Keluaran hasil seperti `verify`: -json = satu objek satu baris di stdout (+ alasan ke stderr bila
// gagal); tanpa -json, OK ke stdout dan penolakan ke stderr.
int emit(Io io, const Result& r, bool json, const std::string& ok_text) {
  if (json) {
    io.out << result_json(r) << "\n";
    if (!r.valid) io.err << to_string(r.status) << ": " << r.message << "\n";
  } else if (r.valid) {
    io.out << ok_text << "\n";
  } else {
    io.err << to_string(r.status) << ": " << r.message << "\n";
  }
  return exit_code(r.status);
}

bool wants_json(std::span<const std::string_view> args) {
  for (const auto& a : args) {
    if (a == "-json" || a == "--json") return true;
  }
  return false;
}

// Seperti parse_or_exit, tetapi dengan -json kesalahan pemakaian juga menghasilkan JSON
// berstatus INPUT_ERROR (sama dengan `verify`).
std::optional<int> parse_json_cmd(std::string_view command, std::string_view summary,
                                  std::span<const Flag> flags,
                                  std::span<const std::string_view> args, Io io, Parsed& parsed) {
  auto r = parse_flags(args, flags);
  if (!r) {
    io.err << "error: " << r.error().message << "\n" << usage_text(command, summary, flags);
    if (wants_json(args))
      io.out << result_json(fail(Status::InputError, r.error().message)) << "\n";
    return exit_code(Status::InputError);
  }
  if (r->help_requested()) {
    io.out << usage_text(command, summary, flags);
    return 0;
  }
  parsed = std::move(*r);
  return std::nullopt;
}

int sbom_sign(std::span<const std::string_view> args, Io io) {
  static constexpr Flag kFlags[] = {
      {"sbom", true, true, "berkas SBOM CycloneDX JSON"},
      {"package", true, true, "nama package (= metadata.component.name)"},
      {"version", true, true, "versi (= metadata.component.version)"},
      {"key", true, true, "privkey PKCS#8 PEM"},
      {"out", true, true, "berkas bundle keluaran"},
  };
  Parsed p;
  if (auto rc = parse_or_exit("sbom sign", "Validate an SBOM and sign it.", kFlags, args, io, p)) {
    return *rc;
  }
  // Semua kegagalan sign = kesalahan input (exit 2), sama dengan `sign`.
  auto text = read_file_capped(std::string(p.value("sbom")), kMaxSbomBytes, "SBOM");
  if (!text) {
    io.err << "error: " << text.error().message << "\n";
    return 2;
  }
  auto info = parse_sbom(*text);
  if (!info) {
    io.err << "error: " << info.error().message << "\n";
    return 2;
  }
  if (info->name != p.value("package") || info->version != p.value("version")) {
    io.err << "error: metadata.component SBOM (" << info->name << " " << info->version
           << ") tidak sama dengan -package/-version (" << p.value("package") << " "
           << p.value("version") << ")\n";
    return 2;
  }
  const std::vector<std::string_view> sign_args = {
      "-file", p.value("sbom"), "-package", p.value("package"), "-version", p.value("version"),
      "-key",  p.value("key"),  "-out",     p.value("out")};
  const int rc = run_sign(sign_args, io);
  if (rc == 0) {
    io.out << "sbom component: " << info->name << " " << info->version << "\n"
           << "sbom artifact sha256: " << info->sha256 << "\n";
  }
  return rc;
}

int sbom_verify(std::span<const std::string_view> args, Io io) {
  static constexpr Flag kFlags[] = {
      {"sbom", true, true, "berkas SBOM yang diverifikasi"},
      {"bundle", true, true, "bundle tanda tangan SBOM"},
      {"trust-store", true, true, "berkas trust store"},
      {"package", true, true, "nama package yang diharapkan"},
      {"version", true, true, "versi yang diharapkan"},
      {"json", false, false, "cetak hasil sebagai satu objek JSON ke stdout"},
  };
  Parsed p;
  if (auto rc = parse_json_cmd("sbom verify", "Verify a signed SBOM.", kFlags, args, io, p)) {
    return *rc;
  }
  const fs::path sbom(std::string(p.value("sbom")));
  Result r =
      verifier::verify(sbom, std::string(p.value("bundle")), std::string(p.value("trust-store")),
                       p.value("package"), p.value("version"));
  std::string sha;
  if (r.valid) {
    // Tanda tangan sah; sekarang isi SBOM-nya sendiri.
    auto text = read_file_capped(sbom, kMaxSbomBytes, "SBOM");
    Outcome<SbomInfo> info = std::unexpected(Error{Status::InputError, ""});
    if (text) {
      info = parse_sbom(*text);
    } else {
      info = std::unexpected(text.error());
    }
    if (!info) {
      r.valid = false;
      r.status = info.error().status;
      r.message = info.error().message;
    } else if (info->name != p.value("package") || info->version != p.value("version")) {
      r.valid = false;
      r.status = Status::MetadataMismatch;
      r.message = "metadata.component SBOM (" + info->name + " " + info->version +
                  ") tidak sama dengan package/version yang diharapkan";
    } else {
      sha = info->sha256;
    }
  }
  return emit(io, r, p.has("json"),
              "OK: SBOM " + r.package + " " + r.version + " (" + r.algorithm + ", keyid " +
                  r.keyid + "), artifact sha256 " + sha);
}

int sbom_check(std::span<const std::string_view> args, Io io) {
  static constexpr Flag kFlags[] = {
      {"sbom", true, true, "berkas SBOM (sudah diverifikasi dengan `sbom verify`)"},
      {"file", true, true, "artefak rilis yang dicek"},
      {"json", false, false, "cetak hasil sebagai satu objek JSON ke stdout"},
  };
  Parsed p;
  if (auto rc = parse_json_cmd("sbom check", "Check that an artifact matches its SBOM.", kFlags,
                               args, io, p)) {
    return *rc;
  }
  const fs::path file(std::string(p.value("file")));
  auto finish = [&](Result r) {
    return emit(
        io, r, p.has("json"),
        "OK: " + file.filename().string() + " cocok dengan SBOM " + r.package + " " + r.version);
  };
  auto text = read_file_capped(std::string(p.value("sbom")), kMaxSbomBytes, "SBOM");
  if (!text) return finish(fail(text.error().status, text.error().message));
  auto info = parse_sbom(*text);
  if (!info) return finish(fail(info.error().status, info.error().message));
  auto sha = sha256_file(file);
  Result r = sha ? (*sha == info->sha256
                        ? ok_result()
                        : fail(Status::ArtifactMismatch, "SHA-256 artefak tidak sama dengan SBOM"))
                 : fail(sha.error().status, sha.error().message);
  r.package = info->name;
  r.version = info->version;
  return finish(r);
}

}  // namespace

int run_sbom(std::span<const std::string_view> args, Io io) {
  if (args.empty()) {
    io.err << "error: aksi sbom hilang\n" << kUsage;
    return 2;
  }
  const std::string_view action = args[0];
  const auto rest = args.subspan(1);
  if (action == "-help" || action == "--help") {
    io.out << kUsage;
    return 0;
  }
  if (action == "sign") return sbom_sign(rest, io);
  if (action == "verify") return sbom_verify(rest, io);
  if (action == "check") return sbom_check(rest, io);
  io.err << "error: aksi sbom tidak dikenal: " << action << "\n" << kUsage;
  return 2;
}

}  // namespace sister_sign::cli
