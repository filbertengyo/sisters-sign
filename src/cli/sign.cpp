#include <ostream>

#include "cli/cli.hpp"

namespace sister_sign::cli {

int run_sign(std::span<const std::string_view> args, Io io) {
  static constexpr Flag kFlags[] = {
      {"file", true, true, "artefak yang ditandatangani"},
      {"package", true, true, "nama package"},
      {"version", true, true, "versi package"},
      {"key", true, true, "privkey PKCS#8 PEM"},
      {"out", true, true, "berkas bundle keluaran"},
  };
  Parsed parsed;
  if (auto rc =
          parse_or_exit("sign", "Sign an artifact and write a bundle.", kFlags, args, io, parsed)) {
    return *rc;
  }
  io.err << "sign: belum diimplementasi\n";
  return 2;
}

}  // namespace sister_sign::cli
