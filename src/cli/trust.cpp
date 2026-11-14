#include <ostream>

#include "cli/cli.hpp"

namespace sister_sign::cli {
namespace {

constexpr std::string_view kUsage =
    "usage: sister-sign trust <add|list|remove> [options]\n"
    "Manage the trust store.\n"
    "  add     trust a public key for a package\n"
    "  list    list trusted keys\n"
    "  remove  remove a trusted key by keyid\n"
    "run 'sister-sign trust <action> -help' for action options\n";

}  // namespace

int run_trust(std::span<const std::string_view> args, Io io) {
  if (args.empty()) {
    io.err << "error: aksi trust hilang\n" << kUsage;
    return 2;
  }
  const std::string_view action = args[0];
  if (action == "-help" || action == "--help") {
    io.out << kUsage;
    return 0;
  }
  if (action != "add" && action != "list" && action != "remove") {
    io.err << "error: aksi trust tidak dikenal: " << action << "\n" << kUsage;
    return 2;
  }
  io.err << "trust " << action << ": belum diimplementasi\n";
  return 2;
}

}  // namespace sister_sign::cli
