#include <doctest/doctest.h>
#include <openssl/pem.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

#include "crypto/crypto.hpp"
#include "test_keys.hpp"

using namespace test;

namespace {

std::string pem_of(const PublicKey& pub) {
  Bio bio = make_mem_bio();
  REQUIRE(PEM_write_bio_PUBKEY(bio.get(), pub.get()) == 1);
  char* data = nullptr;
  const long n = BIO_get_mem_data(bio.get(), &data);
  return std::string(data, static_cast<std::size_t>(n));
}

PublicKey load_pem(const std::string& pem) {
  Bio bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
  REQUIRE(bio != nullptr);
  EvpPkey k(PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr));
  REQUIRE(k != nullptr);
  auto r = PublicKey::from_evp(std::move(k));
  REQUIRE(r.has_value());
  return std::move(*r);
}

std::string id_of(const PublicKey& pub) {
  auto id = keyid(pub);
  REQUIRE(id.has_value());
  return *id;
}

bool is_hex_lower_64(const std::string& s) {
  if (s.size() != 64) return false;
  for (char c : s)
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
  return true;
}

// Susun ulang tubuh base64 PEM dengan lebar baris dan line ending tertentu.
std::string rewrap(const std::string& pem, std::size_t width, const std::string& eol) {
  const std::string head = "-----BEGIN PUBLIC KEY-----";
  const std::string tail = "-----END PUBLIC KEY-----";
  std::string body;
  for (char c : pem.substr(head.size(), pem.find(tail) - head.size())) {
    if (c != '\n' && c != '\r') body.push_back(c);
  }
  std::string out = head + eol;
  for (std::size_t i = 0; i < body.size(); i += width) out += body.substr(i, width) + eol;
  return out + tail + eol;
}

}  // namespace

TEST_CASE("keyid is 64 lowercase hex for all three profiles") {
  for (auto& p : {make_pair("ED25519"), ecdsa_pair()}) {
    CHECK(is_hex_lower_64(id_of(p.pub)));
  }
  PublicKey rsa = [] {
    auto r = PublicKey::from_evp(public_only(generate_rsa(3072).get()));
    REQUIRE(r.has_value());
    return std::move(*r);
  }();
  CHECK(is_hex_lower_64(id_of(rsa)));
}

TEST_CASE("keyid is stable across PEM reformatting") {
  Pair p = ecdsa_pair();
  const std::string pem = pem_of(p.pub);
  const std::string expected = id_of(p.pub);

  CHECK(id_of(load_pem(pem)) == expected);                      // PEM asli (LF, 64 kolom)
  CHECK(id_of(load_pem(rewrap(pem, 64, "\r\n"))) == expected);  // CRLF
  CHECK(id_of(load_pem(rewrap(pem, 64, "\n"))) == expected);
  CHECK(id_of(load_pem(rewrap(pem, 76, "\n"))) == expected);  // lebar baris lain
  CHECK(id_of(load_pem(rewrap(pem, 76, "\r\n"))) == expected);
  CHECK(id_of(load_pem("\n\n" + pem + "\n\n")) == expected);  // baris kosong di sekitar
}

TEST_CASE("keyid is computed from the key, not from the PEM text") {
  // Objek kunci yang masih memuat bagian privat dan objek publik murni dengan SPKI sama harus
  // menghasilkan keyid yang sama.
  EvpPkey full = generate("ED25519");
  auto pure = PublicKey::from_evp(public_only(full.get()));
  EVP_PKEY_up_ref(full.get());
  auto with_private_part = PublicKey::from_evp(EvpPkey(full.get()));
  REQUIRE(pure.has_value());
  REQUIRE(with_private_part.has_value());
  CHECK(id_of(*pure) == id_of(*with_private_part));
  CHECK(id_of(*pure) == id_of(*pure));  // deterministik
}

TEST_CASE("different keys have different keyids") {
  Pair a = ecdsa_pair();
  Pair b = ecdsa_pair();
  CHECK(id_of(a.pub) != id_of(b.pub));
}

TEST_CASE("keyid matches `openssl pkey -pubin -outform DER | sha256sum`") {
  if (std::system("openssl version > /dev/null 2>&1") != 0 ||
      std::system("sha256sum --version > /dev/null 2>&1") != 0) {
    MESSAGE("openssl/sha256sum tidak ada; cek silang dilewati (dicakup T28 interop)");
    return;
  }
  namespace fs = std::filesystem;
  const fs::path dir = fs::temp_directory_path() / "sister_sign_keyid_xcheck";
  fs::create_directories(dir);

  Pair ed = make_pair("ED25519");
  Pair ec = ecdsa_pair();
  for (const Pair* p : {&ed, &ec}) {
    std::ofstream(dir / "pub.pem", std::ios::binary) << pem_of(p->pub);
    const std::string cmd = "openssl pkey -pubin -in " + (dir / "pub.pem").string() +
                            " -outform DER | sha256sum > " + (dir / "out.txt").string();
    REQUIRE(std::system(cmd.c_str()) == 0);
    std::ifstream in(dir / "out.txt");
    std::string line;
    std::getline(in, line);
    CHECK(line.substr(0, 64) == id_of(p->pub));
  }
  fs::remove_all(dir);
}
