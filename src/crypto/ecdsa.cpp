#include "crypto/ecdsa.hpp"

#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/params.h>

namespace sister_sign::crypto {

namespace {

constexpr std::size_t kScalarSize = 32;  // P-256: r dan s masing-masing 32 byte

// ECDSA_SIG dari r||s. Tolak r=0 atau s=0 (verify akan menolak r/s >= n sendiri).
Outcome<EcdsaSig> sig_from_raw(ByteView raw) {
  if (raw.size() != kEcdsaP256SigSize) {
    return make_error(Status::InvalidSignature, "ECDSA: signature harus 64 byte (r||s)");
  }
  Bignum r(BN_bin2bn(raw.data(), kScalarSize, nullptr));
  Bignum s(BN_bin2bn(raw.data() + kScalarSize, kScalarSize, nullptr));
  if (!r || !s) return make_error(Status::InputError, "ECDSA: alokasi BIGNUM gagal");
  if (BN_is_zero(r.get()) || BN_is_zero(s.get())) {
    return make_error(Status::InvalidSignature, "ECDSA: r atau s nol");
  }
  EcdsaSig sig = make_ecdsa_sig();
  if (!sig) return make_error(Status::InputError, "ECDSA: alokasi ECDSA_SIG gagal");
  if (ECDSA_SIG_set0(sig.get(), r.get(), s.get()) != 1) {
    return make_error(Status::InputError, "ECDSA: ECDSA_SIG_set0 gagal");
  }
  r.release();  // dimiliki ECDSA_SIG setelah set0 sukses
  s.release();
  return sig;
}

// r dan s harus di [1, n-1].
bool scalars_in_range(const ECDSA_SIG* sig, EVP_PKEY* key) {
  BIGNUM* order_raw = nullptr;
  if (EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_ORDER, &order_raw) != 1) return false;
  Bignum order(order_raw);
  const BIGNUM* r = nullptr;
  const BIGNUM* s = nullptr;
  ECDSA_SIG_get0(sig, &r, &s);
  return !BN_is_zero(r) && !BN_is_zero(s) && BN_cmp(r, order.get()) < 0 &&
         BN_cmp(s, order.get()) < 0;
}

}  // namespace

Outcome<Bytes> ecdsa_der_to_raw(ByteView der) {
  const unsigned char* p = der.data();
  EcdsaSig sig(d2i_ECDSA_SIG(nullptr, &p, static_cast<long>(der.size())));
  if (!sig || p != der.data() + der.size()) {
    ERR_clear_error();
    return make_error(Status::InvalidSignature, "ECDSA: DER tidak valid");
  }
  const BIGNUM* r = nullptr;
  const BIGNUM* s = nullptr;
  ECDSA_SIG_get0(sig.get(), &r, &s);
  Bytes raw(kEcdsaP256SigSize);
  if (BN_bn2binpad(r, raw.data(), kScalarSize) != static_cast<int>(kScalarSize) ||
      BN_bn2binpad(s, raw.data() + kScalarSize, kScalarSize) != static_cast<int>(kScalarSize)) {
    ERR_clear_error();
    return make_error(Status::InvalidSignature, "ECDSA: r atau s lebih dari 32 byte");
  }
  return raw;
}

Outcome<Bytes> ecdsa_raw_to_der(ByteView raw) {
  auto sig = sig_from_raw(raw);
  if (!sig) return std::unexpected(sig.error());
  const int len = i2d_ECDSA_SIG(sig->get(), nullptr);
  if (len <= 0) return make_error(Status::InputError, "ECDSA: i2d gagal");
  Bytes der(static_cast<std::size_t>(len));
  unsigned char* p = der.data();
  if (i2d_ECDSA_SIG(sig->get(), &p) != len) {
    return make_error(Status::InputError, "ECDSA: i2d gagal");
  }
  return der;
}

Outcome<Bytes> ecdsa_sign(const PrivateKey& key, ByteView message) {
  if (key.algorithm() != Algorithm::EcdsaP256) {
    return make_error(Status::UnsupportedAlgorithm, "kunci bukan ECDSA P-256");
  }
  // Nonce deterministik (RFC 6979, OpenSSL >= 3.2): sign pesan sama -> signature sama, dan
  // menutup risiko nonce reuse akibat RNG buruk.
  unsigned int nonce_type = 1;
  OSSL_PARAM params[] = {OSSL_PARAM_construct_uint(OSSL_SIGNATURE_PARAM_NONCE_TYPE, &nonce_type),
                         OSSL_PARAM_construct_end()};
  EvpMdCtx ctx = make_md_ctx();
  if (!ctx || EVP_DigestSignInit_ex(ctx.get(), nullptr, "SHA256", nullptr, nullptr, key.get(),
                                    params) != 1) {
    return make_error(Status::InputError, "ECDSA sign init gagal: " + openssl_error());
  }
  std::size_t der_len = 0;
  if (EVP_DigestSign(ctx.get(), nullptr, &der_len, message.data(), message.size()) != 1) {
    return make_error(Status::InputError, "ECDSA sign gagal: " + openssl_error());
  }
  Bytes der(der_len);
  if (EVP_DigestSign(ctx.get(), der.data(), &der_len, message.data(), message.size()) != 1) {
    return make_error(Status::InputError, "ECDSA sign gagal: " + openssl_error());
  }
  der.resize(der_len);
  return ecdsa_der_to_raw(der);
}

bool ecdsa_verify(const PublicKey& key, ByteView message, ByteView signature) {
  if (key.algorithm() != Algorithm::EcdsaP256) return false;
  if (signature.size() != kEcdsaP256SigSize) return false;  // DER mentah (~70 byte) ikut ditolak
  auto sig = sig_from_raw(signature);
  if (!sig) return false;
  if (!scalars_in_range(sig->get(), key.get())) {
    ERR_clear_error();
    return false;
  }
  const int len = i2d_ECDSA_SIG(sig->get(), nullptr);
  if (len <= 0) return false;
  Bytes der(static_cast<std::size_t>(len));
  unsigned char* p = der.data();
  if (i2d_ECDSA_SIG(sig->get(), &p) != len) return false;

  EvpMdCtx ctx = make_md_ctx();
  if (!ctx || EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr, key.get()) != 1) {
    ERR_clear_error();
    return false;
  }
  const bool ok =
      EVP_DigestVerify(ctx.get(), der.data(), der.size(), message.data(), message.size()) == 1;
  ERR_clear_error();
  return ok;
}

}  // namespace sister_sign::crypto
