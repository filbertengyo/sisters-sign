#include "cli/cli.hpp"

#include <doctest/doctest.h>

#include <sstream>
#include <string>
#include <vector>

#include "cli/args.hpp"

using namespace sister_sign;
using namespace sister_sign::cli;

namespace {

struct Run {
  int code;
  std::string out;
  std::string err;
};

Run run_cli(std::vector<std::string_view> args) {
  std::ostringstream out, err;
  int code = run(args, Io{out, err});
  return Run{code, out.str(), err.str()};
}

constexpr Flag kFlags[] = {
    {"algorithm", true, true, "algoritma"},
    {"out", true, true, "keluaran"},
    {"force", false, false, "timpa"},
};

Outcome<Parsed> parse(std::vector<std::string_view> args) { return parse_flags(args, kFlags); }

void parse_fails(std::vector<std::string_view> args, std::string_view mention) {
  auto r = parse(args);
  REQUIRE_FALSE(r.has_value());
  CHECK(r.error().status == Status::InputError);
  CHECK(r.error().message.find(mention) != std::string::npos);
}

}  // namespace

// ---- dispatcher --------------------------------------------------------------------------------

TEST_CASE("cli: tanpa argumen -> usage ke stderr, exit 2") {
  auto r = run_cli({});
  CHECK(r.code == 2);
  CHECK(r.out.empty());
  CHECK(r.err.find("usage: sister-sign") != std::string::npos);
}

TEST_CASE("cli: -help dan -version") {
  for (auto flag : {"-help", "--help"}) {
    auto r = run_cli({flag});
    CHECK(r.code == 0);
    CHECK(r.err.empty());
    for (auto cmd : {"keygen", "sign", "verify", "trust"}) {
      CHECK(r.out.find(cmd) != std::string::npos);
    }
  }
  for (auto flag : {"-version", "--version"}) {
    auto r = run_cli({flag});
    CHECK(r.code == 0);
    CHECK(r.out.rfind("sister-sign ", 0) == 0);
  }
}

TEST_CASE("cli: subcommand dan flag global tidak dikenal -> exit 2") {
  auto r = run_cli({"bogus"});
  CHECK(r.code == 2);
  CHECK(r.err.find("unknown command: bogus") != std::string::npos);
  CHECK(run_cli({"-bogus"}).code == 2);
  CHECK(run_cli({""}).code == 2);
}

TEST_CASE("cli: tiap subcommand mencetak usage lewat -help") {
  for (auto cmd : {"keygen", "sign", "verify"}) {
    INFO(cmd);
    auto r = run_cli({cmd, "-help"});
    CHECK(r.code == 0);
    CHECK(r.out.find(std::string("usage: sister-sign ") + cmd) != std::string::npos);
    CHECK(r.err.empty());
  }
  auto t = run_cli({"trust", "-help"});
  CHECK(t.code == 0);
  CHECK(t.out.find("trust <add|list|remove>") != std::string::npos);
}

TEST_CASE("cli: usage menyebut flag tiap subcommand") {
  CHECK(run_cli({"keygen", "-help"}).out.find("-algorithm") != std::string::npos);
  CHECK(run_cli({"keygen", "-help"}).out.find("-force") != std::string::npos);
  CHECK(run_cli({"sign", "-help"}).out.find("-key") != std::string::npos);
  CHECK(run_cli({"verify", "-help"}).out.find("-trust-store") != std::string::npos);
  CHECK(run_cli({"verify", "-help"}).out.find("-json") != std::string::npos);
}

TEST_CASE("cli: parameter wajib hilang -> pesan jelas + exit 2") {
  struct Case {
    std::vector<std::string_view> args;
    std::string_view missing;
  };
  for (const auto& c : std::vector<Case>{
           {{"keygen"}, "-algorithm"},
           {{"keygen", "-algorithm", "ed25519"}, "-out"},
           {{"sign"}, "-file"},
           {{"sign", "-file", "a", "-package", "p", "-version", "1", "-key", "k"}, "-out"},
           {{"verify"}, "-file"},
           {{"verify", "-file", "a", "-bundle", "b", "-trust-store", "t", "-package", "p"},
            "-version"},
       }) {
    INFO(c.missing);
    auto r = run_cli(c.args);
    CHECK(r.code == 2);
    CHECK(r.err.find("flag wajib hilang: " + std::string(c.missing)) != std::string::npos);
    CHECK(r.err.find("usage: sister-sign") != std::string::npos);
  }
}

TEST_CASE("cli: flag tidak dikenal di subcommand -> exit 2") {
  auto r = run_cli({"keygen", "-algorithm", "ed25519", "-out", "x", "-bogus"});
  CHECK(r.code == 2);
  CHECK(r.err.find("flag tidak dikenal: -bogus") != std::string::npos);
  CHECK(run_cli({"verify", "-nope", "1"}).code == 2);
}

TEST_CASE("cli: handler yang belum diisi mengembalikan 2, bukan sukses palsu") {
  // verify baru diisi di T20; selama masih stub harus gagal terang-terangan.
  auto r = run_cli({"verify", "-file", "a", "-bundle", "b", "-trust-store", "t", "-package", "p",
                    "-version", "1", "-json"});
  CHECK(r.code == 2);
  CHECK(r.err.find("belum diimplementasi") != std::string::npos);
}

TEST_CASE("cli: trust butuh aksi yang dikenal") {
  auto none = run_cli({"trust"});
  CHECK(none.code == 2);
  CHECK(none.err.find("aksi trust hilang") != std::string::npos);
  auto bad = run_cli({"trust", "frobnicate"});
  CHECK(bad.code == 2);
  CHECK(bad.err.find("aksi trust tidak dikenal") != std::string::npos);
  for (auto a : {"add", "list", "remove"}) CHECK(run_cli({"trust", a}).code == 2);
}

// ---- parser flag -------------------------------------------------------------------------------

TEST_CASE("args: bentuk `-nama nilai`, `--nama nilai`, `-nama=nilai`") {
  for (auto args : std::vector<std::vector<std::string_view>>{
           {"-algorithm", "ed25519", "-out", "k"},
           {"--algorithm", "ed25519", "--out", "k"},
           {"-algorithm=ed25519", "-out=k"},
           {"-out", "k", "-algorithm", "ed25519"},  // urutan bebas
       }) {
    auto r = parse(args);
    REQUIRE(r.has_value());
    CHECK(r->value("algorithm") == "ed25519");
    CHECK(r->value("out") == "k");
    CHECK_FALSE(r->has("force"));
  }
}

TEST_CASE("args: flag boolean") {
  auto r = parse({"-algorithm", "ed25519", "-out", "k", "-force"});
  REQUIRE(r.has_value());
  CHECK(r->has("force"));
  CHECK(r->value("force").empty());
  parse_fails({"-algorithm", "ed25519", "-out", "k", "-force=1"}, "-force");
}

TEST_CASE("args: nilai boleh berawalan minus selama bukan flag yang dikenal") {
  auto r = parse({"-algorithm", "ed25519", "-out", "-weird-name"});
  REQUIRE(r.has_value());
  CHECK(r->value("out") == "-weird-name");
}

TEST_CASE("args: pelanggaran") {
  SUBCASE("nilai hilang di akhir") { parse_fails({"-algorithm", "ed25519", "-out"}, "-out"); }
  SUBCASE("nilai diganti flag lain") { parse_fails({"-algorithm", "-out", "k"}, "-algorithm"); }
  SUBCASE("nilai kosong") {
    parse_fails({"-algorithm", "", "-out", "k"}, "-algorithm");
    parse_fails({"-algorithm=", "-out", "k"}, "-algorithm");
  }
  SUBCASE("flag ganda (konflik)") {
    parse_fails({"-algorithm", "ed25519", "-algorithm", "rsa-pss", "-out", "k"}, "-algorithm");
    parse_fails({"-algorithm", "ed25519", "-out", "a", "-out=b"}, "-out");
    parse_fails({"-algorithm", "ed25519", "-out", "k", "-force", "-force"}, "-force");
  }
  SUBCASE("flag tidak dikenal") {
    parse_fails({"-algorithm", "ed25519", "-out", "k", "-zzz"}, "-zzz");
  }
  SUBCASE("argumen posisional liar") {
    parse_fails({"-algorithm", "ed25519", "-out", "k", "stray"}, "stray");
    parse_fails({"stray"}, "stray");
    parse_fails({"-"}, "-");
    parse_fails({"--"}, "--");
  }
  SUBCASE("flag wajib hilang") {
    parse_fails({}, "-algorithm");
    parse_fails({"-force"}, "-algorithm");
  }
}

TEST_CASE("args: -help menghentikan parsing tanpa memeriksa flag wajib") {
  auto r = parse({"-help"});
  REQUIRE(r.has_value());
  CHECK(r->help_requested());
  auto r2 = parse({"-algorithm", "ed25519", "--help"});
  REQUIRE(r2.has_value());
  CHECK(r2->help_requested());
}

TEST_CASE("args: usage_text memuat flag wajib dan opsional") {
  auto u = usage_text("keygen", "Ringkasan.", kFlags);
  CHECK(u.find("usage: sister-sign keygen -algorithm <algorithm> -out <out> [-force]") !=
        std::string::npos);
  CHECK(u.find("Ringkasan.") != std::string::npos);
}
