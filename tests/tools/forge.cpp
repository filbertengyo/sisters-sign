// forge: alat bantu KHUSUS TEST untuk membuat dan memanipulasi bundle di kasus e2e.
//
// CLI sister-sign selalu membangun manifest kanonik sendiri, jadi tidak bisa membuat masukan
// yang sengaja rusak (manifest tidak kanonik, signature lama + manifest baru, bit signature
// dibalik, dan sebagainya). Alat ini memakai library inti yang sama dan tidak dipasang/dirilis.
//
//   forge sign-manifest <key.pem> <manifest-file> <out-bundle>   tanda tangani byte berkas apa
//   adanya forge extract-manifest  <bundle> <out>                       tulis byte manifest M forge
//   extract-signature <bundle> <out>                       tulis byte signature forge
//   replace-manifest  <bundle> <manifest-file> <out>       ganti M, signature lama tetap forge
//   flip-sig-bit      <bundle> <out> [bit]                 balik satu bit signature forge reformat
//   <bundle> <out>                       urutan field + whitespace berbeda,
//                                                                string Base64 tidak berubah
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

#include "bundle/bundle.hpp"
#include "crypto/crypto.hpp"
#include "crypto/keyio.hpp"
#include "util/base64.hpp"

using namespace sister_sign;

namespace {

[[noreturn]] void die(const std::string& message) {
  std::cerr << "forge: " << message << "\n";
  std::exit(1);
}

std::string read_file(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  if (!f) die("tidak bisa membaca: " + path);
  return std::string(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
}

void write_file(const std::string& path, const std::string& data) {
  std::ofstream f(path, std::ios::binary | std::ios::trunc);
  f.write(data.data(), static_cast<std::streamsize>(data.size()));
  if (!f) die("tidak bisa menulis: " + path);
}

Bytes to_bytes(const std::string& s) { return Bytes(s.begin(), s.end()); }
std::string to_string(const Bytes& b) { return std::string(b.begin(), b.end()); }

bundle::Bundle read_bundle(const std::string& path) {
  auto b = bundle::read(read_file(path));
  if (!b) die("bundle masukan tidak valid: " + b.error().message);
  return std::move(*b);
}

void write_bundle(const std::string& path, const bundle::Bundle& b) {
  auto text = bundle::write(b);
  if (!text) die(text.error().message);
  write_file(path, *text);
}

}  // namespace

int main(int argc, char** argv) {
  std::vector<std::string> a(argv + 1, argv + argc);
  if (a.empty()) die("perintah hilang");
  const std::string& cmd = a[0];

  if (cmd == "sign-manifest" && a.size() == 4) {
    auto key = crypto::read_private_key(a[1]);
    if (!key) die("privkey: " + key.error().message);
    const Bytes m = to_bytes(read_file(a[2]));
    auto sig = crypto::sign(*key, m);
    if (!sig) die("sign: " + sig.error().message);
    write_bundle(a[3], bundle::Bundle{m, *sig});
  } else if (cmd == "extract-manifest" && a.size() == 3) {
    write_file(a[2], to_string(read_bundle(a[1]).manifest));
  } else if (cmd == "extract-signature" && a.size() == 3) {
    write_file(a[2], to_string(read_bundle(a[1]).signature));
  } else if (cmd == "replace-manifest" && a.size() == 4) {
    bundle::Bundle b = read_bundle(a[1]);
    b.manifest = to_bytes(read_file(a[2]));
    write_bundle(a[3], b);
  } else if (cmd == "flip-sig-bit" && (a.size() == 3 || a.size() == 4)) {
    bundle::Bundle b = read_bundle(a[1]);
    const std::size_t bit = a.size() == 4 ? std::stoul(a[3]) : 0;
    if (bit / 8 >= b.signature.size()) die("indeks bit di luar signature");
    b.signature[bit / 8] ^= static_cast<std::uint8_t>(1u << (bit % 8));
    write_bundle(a[2], b);
  } else if (cmd == "reformat" && a.size() == 3) {
    const bundle::Bundle b = read_bundle(a[1]);
    // Urutan field dibalik, whitespace beragam (spasi, tab, CRLF); isi Base64 tetap sama.
    const std::string text = "{\r\n\t\"signature_b64\" :\n  \"" + util::base64_encode(b.signature) +
                             "\" ,\n\t\"manifest_b64\":\t\"" + util::base64_encode(b.manifest) +
                             "\"  ,\r\n  \"schema\"  :  \"" + std::string(bundle::kSchema) +
                             "\"\r\n}\r\n";
    write_file(a[2], text);
  } else {
    die("perintah/argumen tidak dikenal: " + cmd);
  }
  return 0;
}
