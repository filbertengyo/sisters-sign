// Contoh API library: sign lalu verify sebuah artefak tanpa CLI, memakai modul yang sama
// dengan `sister-sign sign` / `sister-sign verify`. Dibangun dan dijalankan oleh ctest
// (api_example_sign_verify), jadi contoh di dokumentasi API selalu benar-benar jalan.
//
//   api_example_sign_verify <direktori-kerja-kosong>
//
// Exit 0 bila artefak sah diterima (OK) dan artefak yang diubah ditolak (ARTIFACT_MISMATCH).
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#include "bundle/bundle.hpp"
#include "cli/cli.hpp"
#include "crypto/crypto.hpp"
#include "crypto/keyio.hpp"
#include "manifest/manifest.hpp"
#include "trust/trust.hpp"
#include "util/hash.hpp"
#include "util/hex.hpp"
#include "verify/verify.hpp"

namespace fs = std::filesystem;
using namespace sister_sign;

namespace {

int die(const std::string& what, const Error& e) {
  std::cerr << what << ": " << to_string(e.status) << ": " << e.message << "\n";
  return 1;
}

void write_file(const fs::path& p, const std::string& data) {
  std::ofstream(p, std::ios::binary) << data;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cerr << "usage: api_example_sign_verify <empty-work-dir>\n";
    return 2;
  }
  const fs::path dir = argv[1];
  fs::create_directories(dir);
  const fs::path artifact = dir / "app.bin";
  const std::string content = "isi artefak rilis";
  write_file(artifact, content);

  //! [sign]
  // 1. Kunci baru (Ed25519). Profil algoritma selalu diturunkan dari kunci.
  auto pair = crypto::generate_keypair(crypto::Algorithm::Ed25519);
  if (!pair) return die("keygen", pair.error());
  auto id = crypto::keyid(pair->pub);  // hex(SHA-256(DER SPKI)), 64 karakter
  if (!id) return die("keyid", id.error());

  // 2. Manifest kanonik M yang mengikat package, versi, kunci, dan isi artefak.
  const Bytes data(content.begin(), content.end());
  auto digest = util::sha256(data);  // untuk berkas besar: util::Sha256 (streaming)
  if (!digest) return die("sha256", digest.error());
  manifest::Manifest m;
  m.package = "demo";
  m.version = "1.0.0";
  m.algorithm = std::string(manifest::algorithm_name(pair->priv.algorithm()));
  m.keyid = *id;
  m.artifact = {artifact.filename().string(), data.size(), util::hex_lower(*digest)};
  auto m_bytes = manifest::serialize(m);
  if (!m_bytes) return die("manifest", m_bytes.error());
  const Bytes manifest_bytes(m_bytes->begin(), m_bytes->end());

  // 3. Tanda tangan atas byte M apa adanya (tanpa pre-hash), lalu bungkus jadi bundle.
  auto sig = crypto::sign(pair->priv, manifest_bytes);
  if (!sig) return die("sign", sig.error());
  auto bundle_json = bundle::write({manifest_bytes, *sig});
  if (!bundle_json) return die("bundle", bundle_json.error());
  write_file(dir / "app.bundle.json", *bundle_json);
  //! [sign]

  //! [trust]
  // 4. Trust store: satu-satunya sumber pubkey saat verify. Kunci dipercaya per package.
  trust::TrustStore store;
  if (auto r = store.add(pair->pub, "demo"); !r) return die("trust add", r.error());
  if (auto r = store.save(dir / "trust.json"); !r) return die("trust save", r.error());
  //! [trust]

  //! [verify]
  // 5. Verify (Algoritma 2): berhenti di kegagalan pertama; exit_code() memetakan status.
  Result ok =
      verifier::verify(artifact, dir / "app.bundle.json", dir / "trust.json", "demo", "1.0.0");
  std::cout << cli::result_json(ok) << "\n";  // sama dengan output `verify -json`
  if (!ok.valid || ok.status != Status::Ok || exit_code(ok.status) != 0) return 1;

  // Artefak yang diubah setelah sign ditolak.
  write_file(artifact, "isi artefak palsu");
  Result bad =
      verifier::verify(artifact, dir / "app.bundle.json", dir / "trust.json", "demo", "1.0.0");
  std::cout << cli::result_json(bad) << "\n";
  if (bad.valid || bad.status != Status::ArtifactMismatch || exit_code(bad.status) != 1) return 1;
  //! [verify]
  return 0;
}
