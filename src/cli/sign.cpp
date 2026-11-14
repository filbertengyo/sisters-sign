#include <cstdint>
#include <filesystem>
#include <fstream>
#include <ostream>
#include <string>

#include "bundle/bundle.hpp"
#include "cli/cli.hpp"
#include "crypto/keyio.hpp"
#include "manifest/manifest.hpp"
#include "util/hash.hpp"
#include "util/hex.hpp"

namespace sister_sign::cli {
namespace {

namespace fs = std::filesystem;

// Semua kegagalan sign (berkas tidak ada, kunci rusak, metadata di luar pola, out tidak bisa
// ditulis) adalah kesalahan input pengguna -> exit 2.
int fail(Io io, const std::string& message) {
  io.err << "error: " << message << "\n";
  return 2;
}

struct FileDigest {
  std::uint64_t size = 0;
  std::string sha256_hex;
};

// Hash streaming: berkas besar tidak dimuat penuh ke memori.
Outcome<FileDigest> digest_file(const fs::path& path) {
  std::error_code ec;
  if (!fs::is_regular_file(path, ec)) {
    return make_error(Status::InputError, "bukan berkas biasa atau tidak ada: " + path.string());
  }
  std::ifstream in(path, std::ios::binary);
  if (!in) return make_error(Status::InputError, "tidak bisa membuka berkas: " + path.string());

  util::Sha256 hasher;
  FileDigest out;
  Bytes buf(64 * 1024);
  while (true) {
    in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
    const auto n = static_cast<std::size_t>(in.gcount());
    if (n > 0) {
      if (auto r = hasher.update(ByteView(buf.data(), n)); !r) return std::unexpected(r.error());
      out.size += n;
      if (out.size > manifest::kMaxSize) {
        return make_error(Status::InputError, "berkas terlalu besar");
      }
    }
    if (in.eof()) break;
    if (!in) return make_error(Status::InputError, "gagal membaca berkas: " + path.string());
  }
  auto d = hasher.finish();
  if (!d) return std::unexpected(d.error());
  out.sha256_hex = util::hex_lower(*d);
  return out;
}

}  // namespace

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

  // 1. Metadata dari pengguna harus sesuai pola sebelum menyentuh berkas apa pun.
  if (!manifest::valid_package(parsed.value("package"))) {
    return fail(io, "-package tidak sesuai pola ^[a-z0-9][a-z0-9._-]{0,63}$");
  }
  if (!manifest::valid_version(parsed.value("version"))) {
    return fail(io, "-version tidak sesuai pola ^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$");
  }
  const fs::path file(std::string(parsed.value("file")));
  const std::string name = file.filename().string();
  if (!manifest::valid_artifact_name(name)) {
    return fail(io, "nama berkas artefak tidak sesuai pola ^[A-Za-z0-9._-]{1,255}$: " + name);
  }

  // 2. Kunci; profil algoritma diturunkan dari kunci.
  auto priv = crypto::read_private_key(std::string(parsed.value("key")));
  if (!priv) return fail(io, priv.error().message);
  auto pub = crypto::public_key_of(*priv);
  if (!pub) return fail(io, pub.error().message);
  auto id = crypto::keyid(*pub);
  if (!id) return fail(io, id.error().message);

  // 3. Artefak.
  auto digest = digest_file(file);
  if (!digest) return fail(io, digest.error().message);

  // 4. Manifest kanonik M, lalu tanda tangan atas byte M.
  manifest::Manifest m;
  m.package = std::string(parsed.value("package"));
  m.version = std::string(parsed.value("version"));
  m.algorithm = std::string(manifest::algorithm_name(priv->algorithm()));
  m.keyid = *id;
  m.artifact = manifest::ArtifactInfo{name, digest->size, digest->sha256_hex};
  auto m_bytes = manifest::serialize(m);
  if (!m_bytes) return fail(io, m_bytes.error().message);
  const Bytes manifest_bytes(m_bytes->begin(), m_bytes->end());

  auto sig = crypto::sign(*priv, manifest_bytes);
  if (!sig) return fail(io, sig.error().message);
  if (!crypto::verify(*pub, manifest_bytes, *sig)) {
    return fail(io, "tanda tangan yang dihasilkan gagal diverifikasi sendiri");
  }

  // 5. Bundle.
  auto text = bundle::write(bundle::Bundle{manifest_bytes, *sig});
  if (!text) return fail(io, text.error().message);

  const fs::path out_path(std::string(parsed.value("out")));
  {
    std::ofstream out(out_path, std::ios::binary | std::ios::trunc);
    out.write(text->data(), static_cast<std::streamsize>(text->size()));
    out.flush();
    if (!out) {
      out.close();
      std::error_code ec;
      fs::remove(out_path, ec);
      return fail(io, "tidak bisa menulis bundle: " + out_path.string());
    }
  }

  io.out << "signed " << name << " (" << digest->size << " bytes)\n"
         << "algorithm: " << m.algorithm << "\n"
         << "keyid: " << *id << "\n"
         << "bundle: " << out_path.string() << "\n";
  return 0;
}

}  // namespace sister_sign::cli
