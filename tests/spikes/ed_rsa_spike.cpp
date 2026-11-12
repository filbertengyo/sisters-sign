// Spike C (T04): panggilan EVP yang benar untuk Ed25519 (one-shot) dan RSA-PSS 3072.
// Ringkasan hasil + snippet final ada di docs/spike-c.md; dipakai T07 (Ed25519) dan T09 (RSA-PSS).
//
// Bukan kode produksi: deleter lokal di bawah nanti diganti RAII dari crypto/raii.hpp (T06).
// Jalankan lewat `ctest -R spike_c`. Set SPIKE_C_DUMP=<dir> untuk menulis pubkey/pesan/sig
// agar bisa dicek silang dengan CLI `openssl` (perintahnya ada di docs/spike-c.md).
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

using Bytes = std::vector<std::uint8_t>;
using ByteView = std::span<const std::uint8_t>;

struct PkeyFree {
  void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};
struct PkeyCtxFree {
  void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); }
};
struct MdCtxFree {
  void operator()(EVP_MD_CTX* p) const { EVP_MD_CTX_free(p); }
};
struct BnFree {
  void operator()(BIGNUM* p) const { BN_free(p); }
};
struct BioFree {
  void operator()(BIO* p) const { BIO_free(p); }
};
using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyFree>;
using PkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, PkeyCtxFree>;
using MdCtxPtr = std::unique_ptr<EVP_MD_CTX, MdCtxFree>;
using BnPtr = std::unique_ptr<BIGNUM, BnFree>;
using BioPtr = std::unique_ptr<BIO, BioFree>;

Bytes to_bytes(std::string_view s) { return Bytes(s.begin(), s.end()); }

// Contoh pesan M (bentuk manifest final ditentukan T12; isi tidak penting untuk spike ini).
const Bytes kMsg =
    to_bytes(R"({"schema":"sister-sign/manifest/v1","package":"demo","version":"1.0.0"})");

Bytes flip_bit(Bytes b, std::size_t byte_index) {
  b.at(byte_index) ^= 0x01;
  return b;
}

// Ambil kunci publik saja lewat DER SPKI (i2d_PUBKEY -> d2i_PUBKEY), sama seperti pubkey yang
// nanti dibaca dari trust store. Memastikan verify tidak diam-diam memakai bagian privat.
PkeyPtr public_only(EVP_PKEY* key) {
  unsigned char* der = nullptr;
  const int len = i2d_PUBKEY(key, &der);
  if (len <= 0) return nullptr;
  const unsigned char* p = der;
  PkeyPtr pub(d2i_PUBKEY(nullptr, &p, len));
  OPENSSL_free(der);
  return pub;
}

int spki_der_len(EVP_PKEY* key) { return i2d_PUBKEY(key, nullptr); }

// ---------------------------------------------------------------------------------------------
// Ed25519: one-shot EVP_DigestSign / EVP_DigestVerify, md = NULL, pesan M apa adanya.
// ---------------------------------------------------------------------------------------------

PkeyPtr gen_ed25519() { return PkeyPtr(EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519")); }

std::optional<Bytes> ed25519_sign(EVP_PKEY* key, ByteView msg) {
  MdCtxPtr ctx(EVP_MD_CTX_new());
  if (!ctx || EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, key) != 1) {
    return std::nullopt;
  }
  Bytes sig(static_cast<std::size_t>(EVP_PKEY_get_size(key)));
  std::size_t len = sig.size();
  if (EVP_DigestSign(ctx.get(), sig.data(), &len, msg.data(), msg.size()) != 1) {
    return std::nullopt;
  }
  sig.resize(len);
  return sig;
}

// Sengaja TANPA cek panjang supaya terlihat apa yang dilakukan OpenSSL sendiri.
bool ed25519_verify_raw(EVP_PKEY* pub, ByteView msg, ByteView sig) {
  MdCtxPtr ctx(EVP_MD_CTX_new());
  if (!ctx || EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, pub) != 1) return false;
  // 1 = valid, 0 = sig salah, <0 = error lain. Hanya 1 yang boleh dianggap sukses.
  const bool ok = EVP_DigestVerify(ctx.get(), sig.data(), sig.size(), msg.data(), msg.size()) == 1;
  ERR_clear_error();
  return ok;
}

// ---------------------------------------------------------------------------------------------
// RSA-PSS 3072: EVP_DigestSignInit(SHA-256) + padding PSS + salt 32 + MGF1-SHA256.
// ---------------------------------------------------------------------------------------------

constexpr int kRsaBits = 3072;
constexpr int kPssSaltLen = 32;

struct PssParams {
  bool set_padding = true;       // false = biarkan default (PKCS#1 v1.5)
  bool set_saltlen = true;       // false = biarkan default OpenSSL (beda antar versi!)
  int saltlen = kPssSaltLen;     // boleh nilai khusus RSA_PSS_SALTLEN_*
  const EVP_MD* mgf1 = nullptr;  // nullptr = SHA-256
};

bool apply_pss(EVP_PKEY_CTX* pctx, const PssParams& p) {
  if (p.set_padding && EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0) {
    return false;
  }
  if (!p.set_padding) return true;  // salt/MGF1 hanya bermakna untuk PSS
  if (p.set_saltlen && EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, p.saltlen) <= 0) return false;
  const EVP_MD* mgf1 = p.mgf1 != nullptr ? p.mgf1 : EVP_sha256();
  return EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, mgf1) > 0;
}

PkeyPtr gen_rsa(unsigned bits, unsigned long e) {
  PkeyCtxPtr kctx(EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr));
  BnPtr bn_e(BN_new());
  if (!kctx || !bn_e || EVP_PKEY_keygen_init(kctx.get()) <= 0 ||
      EVP_PKEY_CTX_set_rsa_keygen_bits(kctx.get(), static_cast<int>(bits)) <= 0 ||
      BN_set_word(bn_e.get(), e) != 1 ||
      EVP_PKEY_CTX_set1_rsa_keygen_pubexp(kctx.get(), bn_e.get()) <= 0) {
    return nullptr;
  }
  EVP_PKEY* raw = nullptr;
  if (EVP_PKEY_generate(kctx.get(), &raw) <= 0) return nullptr;
  return PkeyPtr(raw);
}

// Cek profil yang dipakai T09/T11: tipe RSA (rsaEncryption), 3072 bit, e = 65537.
bool rsa_e_is_f4(EVP_PKEY* key) {
  BIGNUM* raw = nullptr;
  if (EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_E, &raw) != 1) return false;
  BnPtr e(raw);
  return BN_is_word(e.get(), RSA_F4) == 1;
}

bool rsa_profile_ok(EVP_PKEY* key) {
  return EVP_PKEY_get_base_id(key) == EVP_PKEY_RSA && EVP_PKEY_get_bits(key) == kRsaBits &&
         rsa_e_is_f4(key);
}

std::optional<Bytes> rsa_pss_sign(EVP_PKEY* key, ByteView msg, const PssParams& p = {}) {
  MdCtxPtr ctx(EVP_MD_CTX_new());
  EVP_PKEY_CTX* pctx = nullptr;  // milik ctx, JANGAN di-free sendiri
  if (!ctx || EVP_DigestSignInit(ctx.get(), &pctx, EVP_sha256(), nullptr, key) != 1 ||
      !apply_pss(pctx, p)) {
    return std::nullopt;
  }
  Bytes sig(static_cast<std::size_t>(EVP_PKEY_get_size(key)));
  std::size_t len = sig.size();
  if (EVP_DigestSign(ctx.get(), sig.data(), &len, msg.data(), msg.size()) != 1) {
    return std::nullopt;
  }
  sig.resize(len);
  return sig;
}

bool rsa_pss_verify_raw(EVP_PKEY* pub, ByteView msg, ByteView sig, const PssParams& p = {}) {
  MdCtxPtr ctx(EVP_MD_CTX_new());
  EVP_PKEY_CTX* pctx = nullptr;
  if (!ctx || EVP_DigestVerifyInit(ctx.get(), &pctx, EVP_sha256(), nullptr, pub) != 1 ||
      !apply_pss(pctx, p)) {
    ERR_clear_error();
    return false;
  }
  const bool ok = EVP_DigestVerify(ctx.get(), sig.data(), sig.size(), msg.data(), msg.size()) == 1;
  ERR_clear_error();
  return ok;
}

// Keygen RSA 3072 lambat (detik); buat sekali dan pakai ulang di semua test case.
EVP_PKEY* shared_rsa_key() {
  static PkeyPtr key = gen_rsa(kRsaBits, RSA_F4);
  return key.get();
}

bool openssl_at_least(unsigned long version) { return OpenSSL_version_num() >= version; }

// EVP_DigestSignFinal / EVP_DigestVerifyFinal pada ctx Ed25519 SEGFAULT di OpenSSL < 3.5
// (teruji 3.0.13, 3.0.22, 3.1.8, 3.3.7); di 3.5.7 dan 3.6.1 return 0. Set SPIKE_C_UNSAFE=1
// untuk tetap memanggilnya (reproduksi crash).
bool ed25519_final_is_safe() {
  const char* unsafe = std::getenv("SPIKE_C_UNSAFE");
  return openssl_at_least(0x30500000L) || (unsafe != nullptr && *unsafe == '1');
}

bool write_file(const std::string& path, ByteView data) {
  BioPtr bio(BIO_new_file(path.c_str(), "wb"));
  return bio && BIO_write(bio.get(), data.data(), static_cast<int>(data.size())) ==
                    static_cast<int>(data.size());
}

bool write_pub_pem(const std::string& path, EVP_PKEY* key) {
  BioPtr bio(BIO_new_file(path.c_str(), "w"));
  return bio && PEM_write_bio_PUBKEY(bio.get(), key) == 1;
}

}  // namespace

TEST_CASE("openssl version") {
  MESSAGE("OpenSSL runtime: " << std::string(OpenSSL_version(OPENSSL_VERSION)));
  CHECK(openssl_at_least(0x30000000L));
}

// ---------------------------------------------------------------------------------------------

TEST_CASE("Ed25519: streaming EVP_DigestSignUpdate/Final GAGAL") {
  PkeyPtr key = gen_ed25519();
  REQUIRE(key);
  MdCtxPtr ctx(EVP_MD_CTX_new());
  REQUIRE(EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, key.get()) == 1);
  CHECK(EVP_DigestSignUpdate(ctx.get(), kMsg.data(), kMsg.size()) != 1);
  CHECK(ERR_peek_error() != 0);  // error tercatat di antrean OpenSSL
  ERR_clear_error();

  if (!ed25519_final_is_safe()) {
    MESSAGE("lewati EVP_DigestSignFinal: SEGFAULT di OpenSSL < 3.5");
    return;
  }
  std::size_t len = 0;
  CHECK(EVP_DigestSignFinal(ctx.get(), nullptr, &len) != 1);
  ERR_clear_error();
}

TEST_CASE("Ed25519: streaming EVP_DigestVerifyUpdate/Final juga GAGAL") {
  PkeyPtr key = gen_ed25519();
  REQUIRE(key);
  MdCtxPtr ctx(EVP_MD_CTX_new());
  REQUIRE(EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, key.get()) == 1);
  CHECK(EVP_DigestVerifyUpdate(ctx.get(), kMsg.data(), kMsg.size()) != 1);
  ERR_clear_error();

  if (!ed25519_final_is_safe()) {
    MESSAGE("lewati EVP_DigestVerifyFinal: SEGFAULT di OpenSSL < 3.5");
    return;
  }
  const Bytes sig(64, 0);
  CHECK(EVP_DigestVerifyFinal(ctx.get(), sig.data(), sig.size()) != 1);
  ERR_clear_error();
}

TEST_CASE("Ed25519: md selain NULL ditolak saat init") {
  PkeyPtr key = gen_ed25519();
  REQUIRE(key);
  MdCtxPtr ctx(EVP_MD_CTX_new());
  CHECK(EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr, key.get()) != 1);
  ERR_clear_error();
}

TEST_CASE("Ed25519: one-shot EVP_DigestSign (md=NULL) -> 64 byte, verify OK") {
  PkeyPtr key = gen_ed25519();
  REQUIRE(key);
  CHECK(EVP_PKEY_get_base_id(key.get()) == EVP_PKEY_ED25519);
  CHECK(EVP_PKEY_get_size(key.get()) == 64);
  CHECK(spki_der_len(key.get()) == 44);

  PkeyPtr pub = public_only(key.get());
  REQUIRE(pub);

  const std::optional<Bytes> sig = ed25519_sign(key.get(), kMsg);
  REQUIRE(sig);
  CHECK(sig->size() == 64);
  CHECK(ed25519_verify_raw(pub.get(), kMsg, *sig));

  SUBCASE("deterministik: pesan sama -> sig identik (RFC 8032)") {
    const std::optional<Bytes> again = ed25519_sign(key.get(), kMsg);
    REQUIRE(again);
    CHECK(*again == *sig);
  }
  SUBCASE("flip 1 bit sig / pesan -> gagal") {
    CHECK_FALSE(ed25519_verify_raw(pub.get(), kMsg, flip_bit(*sig, 0)));
    CHECK_FALSE(ed25519_verify_raw(pub.get(), kMsg, flip_bit(*sig, 63)));
    CHECK_FALSE(ed25519_verify_raw(pub.get(), flip_bit(kMsg, 5), *sig));
  }
  SUBCASE("panjang sig 63 / 65 -> gagal") {
    Bytes short_sig(sig->begin(), sig->end() - 1);
    Bytes long_sig = *sig;
    long_sig.push_back(0);
    CHECK_FALSE(ed25519_verify_raw(pub.get(), kMsg, short_sig));
    CHECK_FALSE(ed25519_verify_raw(pub.get(), kMsg, long_sig));
    CHECK_FALSE(ed25519_verify_raw(pub.get(), kMsg, Bytes{}));
  }
  SUBCASE("kunci lain -> gagal") {
    PkeyPtr other = gen_ed25519();
    REQUIRE(other);
    CHECK_FALSE(ed25519_verify_raw(other.get(), kMsg, *sig));
  }
}

TEST_CASE("Ed25519: pesan kosong (data()==nullptr) dan 1 MiB") {
  PkeyPtr key = gen_ed25519();
  REQUIRE(key);
  const Bytes empty;
  const std::optional<Bytes> sig_empty = ed25519_sign(key.get(), empty);
  REQUIRE(sig_empty);
  CHECK(sig_empty->size() == 64);
  CHECK(ed25519_verify_raw(key.get(), empty, *sig_empty));

  const Bytes big(1u << 20, 0xAB);
  const std::optional<Bytes> sig_big = ed25519_sign(key.get(), big);
  REQUIRE(sig_big);
  CHECK(ed25519_verify_raw(key.get(), big, *sig_big));
}

TEST_CASE("Ed25519: ctx tidak dipakai ulang setelah one-shot") {
  // Pola yang benar: satu EVP_MD_CTX per operasi. Setelah EVP_DigestSign sukses, ctx dianggap
  // final; sign kedua dengan ctx yang sama tidak dijamin (versi baru menolak).
  PkeyPtr key = gen_ed25519();
  REQUIRE(key);
  MdCtxPtr ctx(EVP_MD_CTX_new());
  REQUIRE(EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, key.get()) == 1);
  Bytes sig(64);
  std::size_t len = sig.size();
  REQUIRE(EVP_DigestSign(ctx.get(), sig.data(), &len, kMsg.data(), kMsg.size()) == 1);
  len = sig.size();
  const int second = EVP_DigestSign(ctx.get(), sig.data(), &len, kMsg.data(), kMsg.size());
  MESSAGE("EVP_DigestSign kedua pada ctx yang sama -> " << second);
  ERR_clear_error();
}

// ---------------------------------------------------------------------------------------------

TEST_CASE("RSA: keygen 3072 / e=65537 dan cek profil") {
  EVP_PKEY* key = shared_rsa_key();
  REQUIRE(key != nullptr);
  CHECK(EVP_PKEY_get_base_id(key) == EVP_PKEY_RSA);  // rsaEncryption, bukan RSASSA-PSS
  CHECK(EVP_PKEY_get_bits(key) == 3072);
  CHECK(EVP_PKEY_get_size(key) == 384);
  CHECK(spki_der_len(key) == 422);
  CHECK(rsa_e_is_f4(key));
  CHECK(rsa_profile_ok(key));

  PkeyPtr pub = public_only(key);
  REQUIRE(pub);
  CHECK(rsa_profile_ok(pub.get()));  // cek profil bisa dari pubkey saja (trust store)

  SUBCASE("2048 bit ditolak") {
    PkeyPtr small = gen_rsa(2048, RSA_F4);
    REQUIRE(small);
    CHECK(rsa_e_is_f4(small.get()));
    CHECK_FALSE(rsa_profile_ok(small.get()));
  }
  SUBCASE("e=3 ditolak") {
    PkeyPtr e3 = gen_rsa(2048, 3);
    REQUIRE(e3);
    CHECK_FALSE(rsa_e_is_f4(e3.get()));
  }
  SUBCASE("Ed25519 bukan RSA") {
    PkeyPtr ed = gen_ed25519();
    REQUIRE(ed);
    CHECK_FALSE(rsa_profile_ok(ed.get()));
  }
}

TEST_CASE("RSA-PSS: sign SHA-256 / PSS / salt 32 / MGF1-SHA256 -> 384 byte, verify OK") {
  EVP_PKEY* key = shared_rsa_key();
  REQUIRE(key != nullptr);
  PkeyPtr pub = public_only(key);
  REQUIRE(pub);

  const std::optional<Bytes> sig = rsa_pss_sign(key, kMsg);
  REQUIRE(sig);
  CHECK(sig->size() == 384);
  CHECK(rsa_pss_verify_raw(pub.get(), kMsg, *sig));

  SUBCASE("probabilistik: pesan sama -> sig BEDA, dua-duanya verify") {
    const std::optional<Bytes> again = rsa_pss_sign(key, kMsg);
    REQUIRE(again);
    CHECK(*again != *sig);
    CHECK(rsa_pss_verify_raw(pub.get(), kMsg, *again));
  }
  SUBCASE("flip 1 bit sig / pesan -> gagal") {
    CHECK_FALSE(rsa_pss_verify_raw(pub.get(), kMsg, flip_bit(*sig, 0)));
    CHECK_FALSE(rsa_pss_verify_raw(pub.get(), kMsg, flip_bit(*sig, 383)));
    CHECK_FALSE(rsa_pss_verify_raw(pub.get(), flip_bit(kMsg, 5), *sig));
  }
  SUBCASE("panjang sig 383 / 385 -> gagal") {
    Bytes short_sig(sig->begin(), sig->end() - 1);
    Bytes long_sig = *sig;
    long_sig.push_back(0);
    CHECK_FALSE(rsa_pss_verify_raw(pub.get(), kMsg, short_sig));
    CHECK_FALSE(rsa_pss_verify_raw(pub.get(), kMsg, long_sig));
  }
  SUBCASE("salt yang dipakai memang 32 byte") {
    CHECK(rsa_pss_verify_raw(pub.get(), kMsg, *sig, {.saltlen = 32}));
    CHECK(rsa_pss_verify_raw(pub.get(), kMsg, *sig, {.saltlen = RSA_PSS_SALTLEN_DIGEST}));
    CHECK(rsa_pss_verify_raw(pub.get(), kMsg, *sig, {.saltlen = RSA_PSS_SALTLEN_AUTO}));
    CHECK_FALSE(rsa_pss_verify_raw(pub.get(), kMsg, *sig, {.saltlen = 20}));
    CHECK_FALSE(rsa_pss_verify_raw(pub.get(), kMsg, *sig, {.saltlen = 64}));
    CHECK_FALSE(rsa_pss_verify_raw(pub.get(), kMsg, *sig, {.saltlen = RSA_PSS_SALTLEN_MAX}));
  }
  SUBCASE("MGF1 memang SHA-256 (default MGF1 = md signature)") {
    CHECK(rsa_pss_verify_raw(pub.get(), kMsg, *sig, {.mgf1 = EVP_sha256()}));
    CHECK_FALSE(rsa_pss_verify_raw(pub.get(), kMsg, *sig, {.mgf1 = EVP_sha1()}));
    CHECK_FALSE(rsa_pss_verify_raw(pub.get(), kMsg, *sig, {.mgf1 = EVP_sha384()}));
  }
  SUBCASE("verify tanpa padding PSS (default PKCS#1 v1.5) -> gagal") {
    CHECK_FALSE(rsa_pss_verify_raw(pub.get(), kMsg, *sig, {.set_padding = false}));
  }
  SUBCASE("kunci lain -> gagal") {
    PkeyPtr other = gen_rsa(2048, RSA_F4);
    REQUIRE(other);
    CHECK_FALSE(rsa_pss_verify_raw(other.get(), kMsg, *sig));
  }
}

TEST_CASE("RSA-PSS: salt default OpenSSL beda antar versi -> WAJIB set saltlen 32") {
  // OpenSSL 3.0: default salt saat sign = maksimum (384 - 32 - 2 = 350 byte).
  // OpenSSL >= 3.1: default = RSA_PSS_SALTLEN_AUTO_DIGEST_MAX -> min(maks, 32) = 32 byte.
  EVP_PKEY* key = shared_rsa_key();
  REQUIRE(key != nullptr);
  const std::optional<Bytes> sig = rsa_pss_sign(key, kMsg, {.set_saltlen = false});
  REQUIRE(sig);
  const bool new_default = openssl_at_least(0x30100000L);
  MESSAGE("salt default = " << std::string(new_default ? "32 (>= 3.1)" : "maks/350 (3.0)"));
  CHECK(rsa_pss_verify_raw(key, kMsg, *sig, {.saltlen = 32}) == new_default);
  CHECK(rsa_pss_verify_raw(key, kMsg, *sig, {.saltlen = RSA_PSS_SALTLEN_MAX}) == !new_default);
  // AUTO di sisi verify menerima keduanya -> verifier JANGAN pakai AUTO, pakai 32 eksplisit.
  CHECK(rsa_pss_verify_raw(key, kMsg, *sig, {.saltlen = RSA_PSS_SALTLEN_AUTO}));
}

// ---------------------------------------------------------------------------------------------

TEST_CASE("dump bahan cek silang CLI openssl (hanya jika SPIKE_C_DUMP di-set)") {
  const char* dir_env = std::getenv("SPIKE_C_DUMP");
  if (dir_env == nullptr || *dir_env == '\0') return;
  const std::string dir = dir_env;

  PkeyPtr ed = gen_ed25519();
  REQUIRE(ed);
  const std::optional<Bytes> ed_sig = ed25519_sign(ed.get(), kMsg);
  REQUIRE(ed_sig);
  const std::optional<Bytes> rsa_sig = rsa_pss_sign(shared_rsa_key(), kMsg);
  REQUIRE(rsa_sig);

  CHECK(write_file(dir + "/msg.bin", kMsg));
  CHECK(write_pub_pem(dir + "/ed25519.pub.pem", ed.get()));
  CHECK(write_file(dir + "/ed25519.sig", *ed_sig));
  CHECK(write_pub_pem(dir + "/rsa.pub.pem", shared_rsa_key()));
  CHECK(write_file(dir + "/rsa_pss.sig", *rsa_sig));
  MESSAGE("bahan cek silang ditulis ke " << dir);
}
