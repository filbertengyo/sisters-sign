#include "crypto/keyio.hpp"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <cerrno>
#include <cstring>
#include <fstream>
#include <iterator>

#include "crypto/rsa_pss.hpp"

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace sister_sign::crypto {

namespace {

constexpr std::size_t kMaxKeyFileSize = 64 * 1024;

// Satu blok PEM hasil PEM_read_bio. Datanya (bisa privkey) dibersihkan saat dibebaskan.
class PemBlock {
 public:
  PemBlock() = default;
  PemBlock(const PemBlock&) = delete;
  PemBlock& operator=(const PemBlock&) = delete;
  ~PemBlock() {
    OPENSSL_free(name_);
    OPENSSL_free(header_);
    OPENSSL_clear_free(data_, static_cast<std::size_t>(len_));
  }
  char* name_ = nullptr;
  char* header_ = nullptr;
  unsigned char* data_ = nullptr;
  long len_ = 0;
};

Outcome<std::unique_ptr<PemBlock>> read_single_block(std::string_view pem, const char* label) {
  Bio bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
  if (!bio) return make_error(Status::InputError, "alokasi BIO gagal");
  auto blk = std::make_unique<PemBlock>();
  if (PEM_read_bio(bio.get(), &blk->name_, &blk->header_, &blk->data_, &blk->len_) != 1) {
    ERR_clear_error();
    return make_error(Status::FormatError, "PEM tidak valid");
  }
  if (std::strcmp(blk->name_, label) != 0) {
    return make_error(Status::FormatError, std::string("label PEM harus \"") + label +
                                               "\" (ditemukan: \"" +
                                               std::string(blk->name_).substr(0, 40) + "\")");
  }
  if (blk->header_[0] != '\0') {
    return make_error(Status::FormatError, "header PEM (mis. enkripsi) tidak diterima");
  }
  // Tidak boleh ada blok kedua atau data lain setelahnya (selain whitespace).
  char rest[64];
  for (int n; (n = BIO_read(bio.get(), rest, sizeof(rest))) > 0;) {
    for (int i = 0; i < n; ++i) {
      if (rest[i] != '\n' && rest[i] != '\r' && rest[i] != ' ' && rest[i] != '\t') {
        return make_error(Status::FormatError, "ada data tambahan setelah blok PEM");
      }
    }
  }
  return blk;
}

// Profil yang diizinkan. UNSUPPORTED_ALGORITHM untuk kunci sah yang bukan profil kita.
Outcome<void> validate_profile(EVP_PKEY* k) {
  if (EVP_PKEY_is_a(k, "ED25519")) return {};
  if (EVP_PKEY_is_a(k, "EC")) {
    char group[64] = {};
    std::size_t glen = 0;
    if (EVP_PKEY_get_group_name(k, group, sizeof(group), &glen) != 1 ||
        std::string_view(group, glen) != "prime256v1") {
      return make_error(Status::UnsupportedAlgorithm, "kurva EC harus P-256 (prime256v1)");
    }
    char enc[32] = {};
    std::size_t elen = 0;
    if (EVP_PKEY_get_utf8_string_param(k, OSSL_PKEY_PARAM_EC_ENCODING, enc, sizeof(enc), &elen) !=
            1 ||
        std::string_view(enc, elen) != OSSL_PKEY_EC_ENCODING_GROUP) {
      return make_error(Status::UnsupportedAlgorithm,
                        "parameter kurva harus named curve (bukan explicit)");
    }
    return {};
  }
  if (EVP_PKEY_get_base_id(k) == EVP_PKEY_RSA) {
    if (!rsa_pss_profile_ok(k)) {
      return make_error(Status::UnsupportedAlgorithm, "kunci RSA harus 3072 bit dan e=65537");
    }
    return {};
  }
  return make_error(Status::UnsupportedAlgorithm,
                    "tipe kunci tidak didukung (hanya RSA-PSS 3072, ECDSA P-256, Ed25519)");
}

EvpPkey new_key(Algorithm a) {
  const char* name = a == Algorithm::RsaPss ? "RSA" : a == Algorithm::EcdsaP256 ? "EC" : "ED25519";
  EvpPkeyCtx ctx = make_pkey_ctx(name);
  if (!ctx || EVP_PKEY_keygen_init(ctx.get()) != 1) return nullptr;
  if (a == Algorithm::EcdsaP256) {
    if (EVP_PKEY_CTX_set_group_name(ctx.get(), "prime256v1") != 1) return nullptr;
  } else if (a == Algorithm::RsaPss) {
    Bignum e = make_bignum();
    if (!e || BN_set_word(e.get(), RSA_F4) != 1 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), 3072) <= 0 ||
        EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx.get(), e.get()) <= 0) {
      return nullptr;
    }
  }
  EVP_PKEY* raw = nullptr;
  if (EVP_PKEY_keygen(ctx.get(), &raw) != 1) return nullptr;
  return EvpPkey(raw);
}

Outcome<SecureBuffer> read_file_secure(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return make_error(Status::InputError, "tidak bisa membuka berkas: " + path.string());
  SecureBuffer buf(kMaxKeyFileSize + 1);
  in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
  const auto n = static_cast<std::size_t>(in.gcount());
  if (n > kMaxKeyFileSize) {
    return make_error(Status::InputError, "berkas kunci terlalu besar: " + path.string());
  }
  if (in.bad()) return make_error(Status::InputError, "gagal membaca berkas: " + path.string());
  return SecureBuffer(std::span<const std::uint8_t>(buf.data(), n));
}

Outcome<void> write_file(const std::filesystem::path& path, std::string_view data, bool overwrite,
                         unsigned mode) {
#ifdef _WIN32
  (void)mode;
  std::error_code ec;
  if (!overwrite && std::filesystem::exists(path, ec)) {
    return make_error(Status::InputError, "berkas sudah ada: " + path.string());
  }
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  out.write(data.data(), static_cast<std::streamsize>(data.size()));
  if (!out) return make_error(Status::InputError, "gagal menulis berkas: " + path.string());
  return {};
#else
  const int flags = O_WRONLY | O_CREAT | (overwrite ? O_TRUNC : O_EXCL) | O_CLOEXEC;
  const int fd = ::open(path.c_str(), flags, static_cast<mode_t>(mode));
  if (fd < 0) {
    if (errno == EEXIST) {
      return make_error(Status::InputError, "berkas sudah ada: " + path.string());
    }
    return make_error(Status::InputError, "tidak bisa membuat berkas: " + path.string() + " (" +
                                              std::strerror(errno) + ")");
  }
  // Berkas lama yang di-overwrite bisa saja bermode lebih longgar.
  bool ok = ::fchmod(fd, static_cast<mode_t>(mode)) == 0;
  std::size_t off = 0;
  while (ok && off < data.size()) {
    const ssize_t n = ::write(fd, data.data() + off, data.size() - off);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0)
      ok = false;
    else
      off += static_cast<std::size_t>(n);
  }
  ok = ok && ::fsync(fd) == 0;
  ok = (::close(fd) == 0) && ok;
  if (!ok) return make_error(Status::InputError, "gagal menulis berkas: " + path.string());
  return {};
#endif
}

}  // namespace

// ---- keygen ------------------------------------------------------------------------------------

Outcome<KeyPair> generate_keypair(Algorithm algorithm) {
  EvpPkey key = new_key(algorithm);
  if (!key) return make_error(Status::InputError, "keygen gagal: " + openssl_error());
  auto pub = PublicKey::from_evp([&] {
    unsigned char* der = nullptr;
    const int len = i2d_PUBKEY(key.get(), &der);
    if (len <= 0) return EvpPkey();
    const unsigned char* p = der;
    EvpPkey out(d2i_PUBKEY(nullptr, &p, len));
    OPENSSL_free(der);
    return out;
  }());
  if (!pub) return std::unexpected(pub.error());
  auto priv = PrivateKey::from_evp(std::move(key));
  if (!priv) return std::unexpected(priv.error());
  return KeyPair{std::move(*priv), std::move(*pub)};
}

Outcome<PublicKey> public_key_of(const PrivateKey& key) {
  unsigned char* der = nullptr;
  const int len = i2d_PUBKEY(key.get(), &der);
  if (len <= 0) return make_error(Status::InputError, "encode kunci publik gagal");
  const unsigned char* p = der;
  EvpPkey pub(d2i_PUBKEY(nullptr, &p, len));
  OPENSSL_free(der);
  if (!pub) return make_error(Status::InputError, "decode kunci publik gagal");
  return PublicKey::from_evp(std::move(pub));
}

// ---- PEM ---------------------------------------------------------------------------------------

Outcome<PrivateKey> parse_private_key_pem(std::string_view pem) {
  auto blk = read_single_block(pem, "PRIVATE KEY");
  if (!blk) return std::unexpected(blk.error());
  const unsigned char* p = (*blk)->data_;
  EvpPkey key(d2i_AutoPrivateKey(nullptr, &p, (*blk)->len_));
  if (!key || p != (*blk)->data_ + (*blk)->len_) {
    ERR_clear_error();
    return make_error(Status::FormatError, "PKCS#8 tidak valid");
  }
  if (auto v = validate_profile(key.get()); !v) return std::unexpected(v.error());
  return PrivateKey::from_evp(std::move(key));
}

Outcome<PublicKey> parse_public_key_pem(std::string_view pem) {
  auto blk = read_single_block(pem, "PUBLIC KEY");
  if (!blk) return std::unexpected(blk.error());
  const unsigned char* p = (*blk)->data_;
  EvpPkey key(d2i_PUBKEY(nullptr, &p, (*blk)->len_));
  if (!key || p != (*blk)->data_ + (*blk)->len_) {
    ERR_clear_error();
    return make_error(Status::FormatError, "SPKI tidak valid");
  }
  if (auto v = validate_profile(key.get()); !v) return std::unexpected(v.error());
  return PublicKey::from_evp(std::move(key));
}

Outcome<SecureBuffer> private_key_to_pem(const PrivateKey& key) {
  Bio bio = make_mem_bio();
  if (!bio || PEM_write_bio_PKCS8PrivateKey(bio.get(), key.get(), nullptr, nullptr, 0, nullptr,
                                            nullptr) != 1) {
    ERR_clear_error();
    return make_error(Status::InputError, "encode PKCS#8 gagal");
  }
  char* data = nullptr;
  const long n = BIO_get_mem_data(bio.get(), &data);
  if (n <= 0) return make_error(Status::InputError, "encode PKCS#8 gagal");
  return SecureBuffer(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(data),
                                                    static_cast<std::size_t>(n)));
}

Outcome<std::string> public_key_to_pem(const PublicKey& key) {
  Bio bio = make_mem_bio();
  if (!bio || PEM_write_bio_PUBKEY(bio.get(), key.get()) != 1) {
    ERR_clear_error();
    return make_error(Status::InputError, "encode SPKI gagal");
  }
  char* data = nullptr;
  const long n = BIO_get_mem_data(bio.get(), &data);
  if (n <= 0) return make_error(Status::InputError, "encode SPKI gagal");
  return std::string(data, static_cast<std::size_t>(n));
}

// ---- berkas ------------------------------------------------------------------------------------

Outcome<PrivateKey> read_private_key(const std::filesystem::path& path) {
  auto buf = read_file_secure(path);
  if (!buf) return std::unexpected(buf.error());
  return parse_private_key_pem(
      std::string_view(reinterpret_cast<const char*>(buf->data()), buf->size()));
}

Outcome<PublicKey> read_public_key(const std::filesystem::path& path) {
  auto buf = read_file_secure(path);
  if (!buf) return std::unexpected(buf.error());
  return parse_public_key_pem(
      std::string_view(reinterpret_cast<const char*>(buf->data()), buf->size()));
}

Outcome<void> write_private_key(const std::filesystem::path& path, const PrivateKey& key,
                                bool overwrite) {
  auto pem = private_key_to_pem(key);
  if (!pem) return std::unexpected(pem.error());
  return write_file(path, std::string_view(reinterpret_cast<const char*>(pem->data()), pem->size()),
                    overwrite, 0600);
}

Outcome<void> write_public_key(const std::filesystem::path& path, const PublicKey& key,
                               bool overwrite) {
  auto pem = public_key_to_pem(key);
  if (!pem) return std::unexpected(pem.error());
  return write_file(path, *pem, overwrite, 0644);
}

}  // namespace sister_sign::crypto
