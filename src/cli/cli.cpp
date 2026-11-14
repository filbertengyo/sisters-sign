#include "cli/cli.hpp"

#include <ostream>

#include "cli/args.hpp"
#include "util/version.hpp"

namespace sister_sign::cli {
namespace {

constexpr std::string_view kUsage =
    "sister-sign - sign and verify software artifacts\n"
    "usage: sister-sign <command> [options]\n"
    "commands:\n"
    "  keygen   generate a key pair\n"
    "  sign     sign an artifact and write a bundle\n"
    "  verify   verify an artifact against a bundle and trust store\n"
    "  trust    manage the trust store (add | list | remove)\n"
    "global flags: -help, -version\n"
    "run 'sister-sign <command> -help' for command options\n";

}  // namespace

std::optional<int> parse_or_exit(std::string_view command, std::string_view summary,
                                 std::span<const Flag> flags,
                                 std::span<const std::string_view> args, Io io, Parsed& parsed) {
  auto r = parse_flags(args, flags);
  if (!r) {
    io.err << "error: " << r.error().message << "\n" << usage_text(command, summary, flags);
    return exit_code(r.error().status);
  }
  if (r->help_requested()) {
    io.out << usage_text(command, summary, flags);
    return 0;
  }
  parsed = std::move(*r);
  return std::nullopt;
}

int run(std::span<const std::string_view> args, Io io) {
  if (args.empty()) {
    io.err << kUsage;
    return 2;
  }
  const std::string_view cmd = args[0];
  const auto rest = args.subspan(1);

  if (cmd == "-help" || cmd == "--help") {
    io.out << kUsage;
    return 0;
  }
  if (cmd == "-version" || cmd == "--version") {
    io.out << "sister-sign " << util::version() << "\n";
    return 0;
  }
  if (cmd == "keygen") return run_keygen(rest, io);
  if (cmd == "sign") return run_sign(rest, io);
  if (cmd == "verify") return run_verify(rest, io);
  if (cmd == "trust") return run_trust(rest, io);

  io.err << "unknown command: " << cmd << "\n" << kUsage;
  return 2;
}

}  // namespace sister_sign::cli
