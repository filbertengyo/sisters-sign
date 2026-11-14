#include <filesystem>
#include <ostream>
#include <string>

#include "cli/cli.hpp"
#include "crypto/keyio.hpp"
#include "manifest/manifest.hpp"

namespace sister_sign::cli {
namespace {

namespace fs = std::filesystem;

int fail(Io io, const Error& e) {
  io.err << "error: " << e.message << "\n";
  return exit_code(e.status);
}

}  // namespace

int run_keygen(std::span<const std::string_view> args, Io io) {
  static constexpr Flag kFlags[] = {
      {"algorithm", true, true, "profil algoritma (rsa-pss-sha256 | ecdsa-p256-sha256 | ed25519)"},
      {"out", true, true, "prefix berkas keluaran (<prefix>.key.pem dan <prefix>.pub.pem)"},
      {"force", false, false, "timpa berkas yang sudah ada"},
  };
  Parsed parsed;
  if (auto rc = parse_or_exit("keygen", "Generate a key pair.", kFlags, args, io, parsed)) {
    return *rc;
  }

  // Nilai -algorithm = nama profil (Tabel 2.1), sama dengan field algorithm di manifest.
  crypto::Algorithm algorithm;
  if (!manifest::parse_algorithm_name(parsed.value("algorithm"), algorithm)) {
    io.err << "error: profil algoritma tidak dikenal: " << parsed.value("algorithm")
           << " (pilihan: rsa-pss-sha256, ecdsa-p256-sha256, ed25519)\n";
    return 2;
  }

  const std::string prefix(parsed.value("out"));
  const fs::path key_path = prefix + ".key.pem";
  const fs::path pub_path = prefix + ".pub.pem";
  const bool force = parsed.has("force");

  // Cek sebelum keygen (RSA 3072 butuh waktu) supaya penolakan overwrite cepat dan tidak
  // meninggalkan setengah pasangan.
  std::error_code ec;
  const bool key_existed = fs::exists(key_path, ec);
  const bool pub_existed = fs::exists(pub_path, ec);
  if (!force && (key_existed || pub_existed)) {
    io.err << "error: berkas sudah ada: " << (key_existed ? key_path : pub_path).string()
           << " (gunakan -force untuk menimpa)\n";
    return 2;
  }

  auto pair = crypto::generate_keypair(algorithm);
  if (!pair) return fail(io, pair.error());
  auto id = crypto::keyid(pair->pub);
  if (!id) return fail(io, id.error());

  if (auto r = crypto::write_private_key(key_path, pair->priv, force); !r) {
    return fail(io, r.error());
  }
  if (auto r = crypto::write_public_key(pub_path, pair->pub, force); !r) {
    // Jangan tinggalkan privkey baru tanpa pasangannya.
    if (!key_existed) fs::remove(key_path, ec);
    return fail(io, r.error());
  }

  io.out << "algorithm: " << manifest::algorithm_name(algorithm) << "\n"
         << "private key: " << key_path.string() << "\n"
         << "public key: " << pub_path.string() << "\n"
         << "keyid: " << *id << "\n";
  return 0;
}

}  // namespace sister_sign::cli
