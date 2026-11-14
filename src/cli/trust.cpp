#include "trust/trust.hpp"

#include <algorithm>
#include <ostream>
#include <string>

#include "cli/cli.hpp"
#include "crypto/keyio.hpp"
#include "manifest/manifest.hpp"
#include "util/result.hpp"

namespace sister_sign::cli {
namespace {

constexpr std::string_view kUsage =
    "usage: sister-sign trust <add|list|remove> [options]\n"
    "Manage the trust store.\n"
    "  add     trust a public key for a package\n"
    "  list    list trusted keys\n"
    "  remove  remove a trusted key by keyid\n"
    "run 'sister-sign trust <action> -help' for action options\n";

// Semua kegagalan perintah trust (berkas tidak ada/rusak, kunci rusak, keyid tak ketemu) adalah
// kesalahan input pengguna -> exit 2. Exit 1 hanya untuk penolakan verifikasi.
int fail(Io io, const Error& e) {
  io.err << "error: " << e.message << "\n";
  return 2;
}

int trust_add(std::span<const std::string_view> args, Io io) {
  static constexpr Flag kFlags[] = {
      {"store", true, true, "berkas trust store (dibuat bila belum ada)"},
      {"key", true, true, "pubkey SPKI PEM yang dipercaya"},
      {"package", true, true, "package yang boleh ditandatangani kunci ini"},
  };
  Parsed p;
  if (auto rc =
          parse_or_exit("trust add", "Trust a public key for a package.", kFlags, args, io, p)) {
    return *rc;
  }
  auto key = crypto::read_public_key(std::string(p.value("key")));
  if (!key) return fail(io, key.error());
  auto id = crypto::keyid(*key);
  if (!id) return fail(io, id.error());

  const std::string path(p.value("store"));
  auto store = trust::TrustStore::load_or_empty(path);
  if (!store) return fail(io, store.error());
  if (auto r = store->add(*key, p.value("package")); !r) return fail(io, r.error());
  if (auto r = store->save(path); !r) return fail(io, r.error());

  io.out << "trusted " << *id << " (" << manifest::algorithm_name(key->algorithm())
         << ") for package " << p.value("package") << "\n";
  return 0;
}

int trust_list(std::span<const std::string_view> args, Io io) {
  static constexpr Flag kFlags[] = {
      {"store", true, true, "berkas trust store"},
  };
  Parsed p;
  if (auto rc = parse_or_exit("trust list", "List trusted keys.", kFlags, args, io, p)) return *rc;

  auto store = trust::TrustStore::load(std::string(p.value("store")));
  if (!store) return fail(io, store.error());

  io.out << "KEYID                                                            ALGORITHM   "
            "PACKAGES\n";
  for (const auto& e : store->entries()) {
    std::string name(manifest::algorithm_name(e.algorithm));
    name.resize(std::max<std::size_t>(name.size(), 11), ' ');
    std::string packages;
    for (const auto& pkg : e.packages) {
      if (!packages.empty()) packages += ",";
      packages += pkg;
    }
    io.out << e.keyid << "  " << name << " " << packages << "\n";
  }
  return 0;
}

int trust_remove(std::span<const std::string_view> args, Io io) {
  static constexpr Flag kFlags[] = {
      {"store", true, true, "berkas trust store"},
      {"keyid", true, true, "keyid (64 hex) yang dihapus"},
  };
  Parsed p;
  if (auto rc =
          parse_or_exit("trust remove", "Remove a trusted key by keyid.", kFlags, args, io, p)) {
    return *rc;
  }
  const std::string path(p.value("store"));
  auto store = trust::TrustStore::load(path);
  if (!store) return fail(io, store.error());
  if (auto r = store->remove(p.value("keyid")); !r) return fail(io, r.error());
  if (auto r = store->save(path); !r) return fail(io, r.error());

  io.out << "removed " << p.value("keyid") << "\n";
  return 0;
}

}  // namespace

int run_trust(std::span<const std::string_view> args, Io io) {
  if (args.empty()) {
    io.err << "error: aksi trust hilang\n" << kUsage;
    return 2;
  }
  const std::string_view action = args[0];
  const auto rest = args.subspan(1);
  if (action == "-help" || action == "--help") {
    io.out << kUsage;
    return 0;
  }
  if (action == "add") return trust_add(rest, io);
  if (action == "list") return trust_list(rest, io);
  if (action == "remove") return trust_remove(rest, io);

  io.err << "error: aksi trust tidak dikenal: " << action << "\n" << kUsage;
  return 2;
}

}  // namespace sister_sign::cli
