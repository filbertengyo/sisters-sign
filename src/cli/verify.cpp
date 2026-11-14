#include "verify/verify.hpp"

#include <cstdint>
#include <ostream>
#include <string>

#include "cli/cli.hpp"
#include "util/result.hpp"

namespace sister_sign::cli {
namespace {

// Panjang urutan UTF-8 yang sah di `s[i]`, atau 0 bila tidak sah.
std::size_t utf8_len(std::string_view s, std::size_t i) {
  const auto b = [&](std::size_t k) { return static_cast<unsigned char>(s[k]); };
  const unsigned char c = b(i);
  auto cont = [&](std::size_t k) { return k < s.size() && (b(k) & 0xC0) == 0x80; };
  if (c < 0x80) return 1;
  if (c >= 0xC2 && c <= 0xDF) return cont(i + 1) ? 2 : 0;
  if (c >= 0xE0 && c <= 0xEF) {
    if (!cont(i + 1) || !cont(i + 2)) return 0;
    if (c == 0xE0 && b(i + 1) < 0xA0) return 0;   // overlong
    if (c == 0xED && b(i + 1) >= 0xA0) return 0;  // surrogate
    return 3;
  }
  if (c >= 0xF0 && c <= 0xF4) {
    if (!cont(i + 1) || !cont(i + 2) || !cont(i + 3)) return 0;
    if (c == 0xF0 && b(i + 1) < 0x90) return 0;   // overlong
    if (c == 0xF4 && b(i + 1) >= 0x90) return 0;  // > U+10FFFF
    return 4;
  }
  return 0;
}

// String JSON: escape ", \ dan karakter kontrol; UTF-8 sah dibiarkan; byte tidak sah diganti
// U+FFFD supaya keluaran selalu JSON/UTF-8 yang valid walau masukan pengguna aneh.
void append_json_string(std::string& out, std::string_view s) {
  static constexpr char kHex[] = "0123456789abcdef";
  out += '"';
  for (std::size_t i = 0; i < s.size();) {
    const auto c = static_cast<unsigned char>(s[i]);
    if (c == '"' || c == '\\') {
      out += '\\';
      out += static_cast<char>(c);
      ++i;
    } else if (c < 0x20 || c == 0x7F) {
      out += "\\u00";
      out += kHex[c >> 4];
      out += kHex[c & 0xF];
      ++i;
    } else if (c < 0x80) {
      out += static_cast<char>(c);
      ++i;
    } else if (const std::size_t n = utf8_len(s, i); n > 0) {
      out.append(s.substr(i, n));
      i += n;
    } else {
      out += "\\ufffd";
      ++i;
    }
  }
  out += '"';
}

// Satu objek, satu baris. Urutan field tetap.
std::string to_json(const Result& r) {
  std::string out = R"({"valid":)";
  out += r.valid ? "true" : "false";
  out += R"(,"status":)";
  append_json_string(out, to_string(r.status));
  out += R"(,"message":)";
  append_json_string(out, r.message);
  // Tabel 2.9: string atau null (null bila belum dapat dibaca dari manifest).
  const auto nullable = [&out](std::string_view key, const std::string& value) {
    out += ",\"";
    out += key;
    out += "\":";
    if (value.empty()) {
      out += "null";
    } else {
      append_json_string(out, value);
    }
  };
  nullable("algorithm", r.algorithm);
  nullable("keyid", r.keyid);
  nullable("package", r.package);
  nullable("version", r.version);
  out += "}";
  return out;
}

}  // namespace

int run_verify(std::span<const std::string_view> args, Io io) {
  static constexpr std::string_view kSummary =
      "Verify an artifact against a bundle and trust store.";
  static constexpr Flag kFlags[] = {
      {"file", true, true, "artefak yang diverifikasi"},
      {"bundle", true, true, "berkas bundle"},
      {"trust-store", true, true, "berkas trust store"},
      {"package", true, true, "nama package yang diharapkan"},
      {"version", true, true, "versi yang diharapkan"},
      {"json", false, false, "cetak hasil sebagai satu objek JSON ke stdout"},
  };
  // Tabel 2.10: pada `verify -json`, kesalahan pemakaian juga menghasilkan JSON berstatus
  // INPUT_ERROR (exit 2); pesan dan usage tetap ke stderr.
  bool wants_json = false;
  for (const auto& a : args) wants_json = wants_json || a == "-json" || a == "--json";

  Parsed parsed;
  {
    auto r = parse_flags(args, kFlags);
    if (!r) {
      io.err << "error: " << r.error().message << "\n" << usage_text("verify", kSummary, kFlags);
      if (wants_json) io.out << to_json(fail(Status::InputError, r.error().message)) << "\n";
      return exit_code(Status::InputError);
    }
    if (r->help_requested()) {
      io.out << usage_text("verify", kSummary, kFlags);
      return 0;
    }
    parsed = std::move(*r);
  }

  const Result result = verifier::verify(
      std::string(parsed.value("file")), std::string(parsed.value("bundle")),
      std::string(parsed.value("trust-store")), parsed.value("package"), parsed.value("version"));

  if (parsed.has("json")) {
    // stdout: hanya satu objek JSON + newline. Log (bila gagal) ke stderr.
    io.out << to_json(result) << "\n";
    if (!result.valid) io.err << to_string(result.status) << ": " << result.message << "\n";
  } else if (result.valid) {
    io.out << "OK: " << result.package << " " << result.version << " (" << result.algorithm
           << ", keyid " << result.keyid << ")\n";
  } else {
    io.err << to_string(result.status) << ": " << result.message << "\n";
  }
  return exit_code(result.status);
}

}  // namespace sister_sign::cli
