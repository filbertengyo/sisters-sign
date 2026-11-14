#include <ostream>

#include "cli/cli.hpp"

namespace sister_sign::cli {

int run_verify(std::span<const std::string_view> args, Io io) {
  static constexpr Flag kFlags[] = {
      {"file", true, true, "artefak yang diverifikasi"},
      {"bundle", true, true, "berkas bundle"},
      {"trust-store", true, true, "berkas trust store"},
      {"package", true, true, "nama package yang diharapkan"},
      {"version", true, true, "versi yang diharapkan"},
      {"json", false, false, "cetak hasil sebagai satu objek JSON ke stdout"},
  };
  Parsed parsed;
  if (auto rc = parse_or_exit("verify", "Verify an artifact against a bundle and trust store.",
                              kFlags, args, io, parsed)) {
    return *rc;
  }
  io.err << "verify: belum diimplementasi\n";
  return 2;
}

}  // namespace sister_sign::cli
