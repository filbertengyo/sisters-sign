#include <ostream>

#include "cli/cli.hpp"

namespace sister_sign::cli {

int run_keygen(std::span<const std::string_view> args, Io io) {
  static constexpr Flag kFlags[] = {
      {"algorithm", true, true, "algoritma kunci (rsa-pss | ecdsa | ed25519)"},
      {"out", true, true, "prefix berkas keluaran (<prefix>.key.pem dan <prefix>.pub.pem)"},
      {"force", false, false, "timpa berkas yang sudah ada"},
  };
  Parsed parsed;
  if (auto rc = parse_or_exit("keygen", "Generate a key pair.", kFlags, args, io, parsed)) {
    return *rc;
  }
  io.err << "keygen: belum diimplementasi\n";
  return 2;
}

}  // namespace sister_sign::cli
