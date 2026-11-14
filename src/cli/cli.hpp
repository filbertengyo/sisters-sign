#pragma once
// CLI: dispatcher subcommand. Tidak pernah membaca stdin dan tidak memakai prompt/TTY.
//
// Tiap subcommand punya handler sendiri di berkas sendiri (keygen.cpp, sign.cpp, verify.cpp,
// trust.cpp) supaya pengerjaan paralel tidak bentrok. `args` tidak memuat nama program maupun
// nama subcommand. Exit code: 0 sukses, 2 kesalahan input/penggunaan (lihat util/result.hpp).
#include <iosfwd>
#include <optional>
#include <span>
#include <string_view>

#include "cli/args.hpp"

namespace sister_sign::cli {

struct Io {
  std::ostream& out;
  std::ostream& err;
};

// `args` = argv[1..]. Mengembalikan exit code proses.
int run(std::span<const std::string_view> args, Io io);

// Pembantu handler: parse `args` dengan `flags`. Mengembalikan exit code bila proses harus berhenti
// (-help -> usage ke stdout, 0; galat -> pesan + usage ke stderr, 2), atau nullopt bila lanjut.
std::optional<int> parse_or_exit(std::string_view command, std::string_view summary,
                                 std::span<const Flag> flags,
                                 std::span<const std::string_view> args, Io io, Parsed& parsed);

int run_keygen(std::span<const std::string_view> args, Io io);
int run_sign(std::span<const std::string_view> args, Io io);
int run_verify(std::span<const std::string_view> args, Io io);
int run_trust(std::span<const std::string_view> args, Io io);

}  // namespace sister_sign::cli
