#include "verify/verify.hpp"

#include <cstdint>
#include <fstream>
#include <string>

#include "bundle/bundle.hpp"
#include "crypto/crypto.hpp"
#include "manifest/manifest.hpp"
#include "trust/trust.hpp"
#include "util/hash.hpp"
#include "util/hex.hpp"

namespace sister_sign::verifier {
namespace {

namespace fs = std::filesystem;

// Baca berkas sampai `cap` + 1 byte: cukup untuk membuat parser menolak berkas kelewat besar tanpa
// memuat berkas sebesar apa pun ke memori.
Outcome<std::string> read_capped(const fs::path& path, std::size_t cap, const char* what) {
  std::error_code ec;
  if (!fs::is_regular_file(path, ec)) {
    return make_error(Status::InputError,
                      std::string(what) + " tidak ada atau bukan berkas biasa: " + path.string());
  }
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return make_error(Status::InputError,
                      std::string(what) + " tidak bisa dibuka: " + path.string());
  }
  std::string data(cap + 1, '\0');
  in.read(data.data(), static_cast<std::streamsize>(data.size()));
  if (in.bad()) {
    return make_error(Status::InputError, std::string(what) + " gagal dibaca: " + path.string());
  }
  data.resize(static_cast<std::size_t>(in.gcount()));
  return data;
}

Outcome<std::string> sha256_of_file(const fs::path& path, std::uint64_t& size) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return make_error(Status::InputError, "artefak tidak bisa dibuka: " + path.string());
  util::Sha256 hasher;
  Bytes buf(64 * 1024);
  size = 0;
  while (true) {
    in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
    const auto n = static_cast<std::size_t>(in.gcount());
    if (n > 0) {
      if (auto r = hasher.update(ByteView(buf.data(), n)); !r) return std::unexpected(r.error());
      size += n;
    }
    if (in.eof()) break;
    if (!in) return make_error(Status::InputError, "artefak gagal dibaca: " + path.string());
  }
  auto d = hasher.finish();
  if (!d) return std::unexpected(d.error());
  return util::hex_lower(*d);
}

Result failure(Status status, std::string message) { return fail(status, std::move(message)); }

Result failure(const Error& e) { return fail(e.status, e.message); }

}  // namespace

Result verify(const fs::path& file, const fs::path& bundle_path, const fs::path& trust_store_path,
              std::string_view package, std::string_view version) {
  // ---- 1. INPUT_ERROR --------------------------------------------------------------------------
  std::error_code ec;
  if (!fs::is_regular_file(file, ec)) {
    return failure(Status::InputError,
                   "artefak tidak ada atau bukan berkas biasa: " + file.string());
  }
  {
    std::ifstream probe(file, std::ios::binary);
    if (!probe) return failure(Status::InputError, "artefak tidak bisa dibuka: " + file.string());
  }
  auto bundle_text = read_capped(bundle_path, bundle::kMaxBundleBytes, "bundle");
  if (!bundle_text) return failure(bundle_text.error());
  auto store_text = read_capped(trust_store_path, trust::kMaxStoreBytes, "trust store");
  if (!store_text) return failure(store_text.error());

  // ---- 2. FORMAT_ERROR -------------------------------------------------------------------------
  auto bundle = bundle::read(*bundle_text);
  if (!bundle) return failure(bundle.error());
  const std::string m_text(bundle->manifest.begin(), bundle->manifest.end());
  auto manifest = manifest::parse(m_text);
  if (!manifest) return failure(manifest.error());
  auto store = trust::TrustStore::parse(*store_text);
  if (!store) return failure(store.error());

  // Manifest berhasil dibaca: bagi spek (Tabel 2.9) field-nya boleh dilaporkan dari sini, hanya
  // sebagai penjelasan hasil dan bukan data yang sah sebelum tanda tangan terbukti.
  auto described = [&](Status status, std::string message) {
    Result r = fail(status, std::move(message));
    r.algorithm = manifest->algorithm;
    r.keyid = manifest->keyid;
    r.package = manifest->package;
    r.version = manifest->version;
    return r;
  };

  // ---- 3. UNSUPPORTED_ALGORITHM ----------------------------------------------------------------
  crypto::Algorithm algorithm;
  if (!manifest::parse_algorithm_name(manifest->algorithm, algorithm)) {
    return described(Status::UnsupportedAlgorithm,
                     "algoritma tidak didukung: " + manifest->algorithm);
  }

  // ---- 4. KEY_NOT_TRUSTED ----------------------------------------------------------------------
  // Satu-satunya pencarian kunci: keyid + package yang DIHARAPKAN PENGGUNA + profil dari manifest.
  // Tidak ada fallback ke kunci, profil, atau trust store lain.
  auto key = store->lookup(manifest->keyid, package, algorithm);
  if (!key) return described(key.error().status, key.error().message);

  // ---- 5. INVALID_SIGNATURE --------------------------------------------------------------------
  // Atas byte M persis seperti di bundle (bukan hasil serialisasi ulang).
  if (!crypto::verify(**key, bundle->manifest, bundle->signature)) {
    return described(Status::InvalidSignature, "tanda tangan tidak valid");
  }

  // ---- 6. METADATA_MISMATCH --------------------------------------------------------------------
  if (manifest->package != package) {
    return described(Status::MetadataMismatch, "package tidak cocok: manifest '" +
                                                   manifest->package + "', diharapkan '" +
                                                   std::string(package) + "'");
  }
  if (manifest->version != version) {
    return described(Status::MetadataMismatch, "version tidak cocok: manifest '" +
                                                   manifest->version + "', diharapkan '" +
                                                   std::string(version) + "'");
  }
  const std::string basename = file.filename().string();
  if (manifest->artifact.name != basename) {
    return described(Status::MetadataMismatch, "nama artefak tidak cocok: manifest '" +
                                                   manifest->artifact.name + "', berkas '" +
                                                   basename + "'");
  }

  // ---- 7. ARTIFACT_MISMATCH --------------------------------------------------------------------
  // Ukuran dicek dulu (murah), baru SHA-256.
  const auto actual_size = fs::file_size(file, ec);
  if (ec) return failure(Status::InputError, "ukuran artefak tidak terbaca: " + file.string());
  if (actual_size != manifest->artifact.size) {
    return described(Status::ArtifactMismatch, "ukuran artefak tidak cocok: manifest " +
                                                   std::to_string(manifest->artifact.size) +
                                                   ", berkas " + std::to_string(actual_size));
  }
  std::uint64_t hashed = 0;
  auto sha = sha256_of_file(file, hashed);
  if (!sha) return failure(sha.error());
  if (hashed != manifest->artifact.size || *sha != manifest->artifact.sha256) {
    return described(Status::ArtifactMismatch, "SHA-256 artefak tidak cocok");
  }

  // ---- OK --------------------------------------------------------------------------------------
  Result ok = ok_result();
  ok.algorithm = manifest->algorithm;
  ok.keyid = manifest->keyid;
  ok.package = manifest->package;
  ok.version = manifest->version;
  return ok;
}

}  // namespace sister_sign::verifier
