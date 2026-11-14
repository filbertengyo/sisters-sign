#include "crypto/rsa_pss.hpp"

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

namespace sister_sign::crypto {

namespace {

constexpr int kRsaBits = 3072;
constexpr int kSaltLen = 32;

// Parameter PSS harus di-set eksplisit: salt default OpenSSL berbeda antar versi (3.0 = maks,
// >= 3.1 = 32), dan verifier tidak boleh memakai SALTLEN_AUTO (menerima salt apa saja).
bool apply_pss(EVP_PKEY_CTX* pctx) {
  return EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) > 0 &&
         EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, kSaltLen) > 0 &&
         EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha256()) > 0;
}

}  // namespace

bool rsa_pss_profile_ok(EVP_PKEY* key) {
  if (key == nullptr || EVP_PKEY_get_base_id(key) != EVP_PKEY_RSA) return false;
  if (EVP_PKEY_get_bits(key) != kRsaBits) return false;
  BIGNUM* raw = nullptr;
  if (EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_E, &raw) != 1) return false;
  Bignum e(raw);
  return BN_is_word(e.get(), RSA_F4) == 1;
}

Outcome<Bytes> rsa_pss_sign(const PrivateKey& key, ByteView message) {
  if (key.algorithm() != Algorithm::RsaPss) {
    return make_error(Status::UnsupportedAlgorithm, "kunci bukan RSA-PSS");
  }
  if (!rsa_pss_profile_ok(key.get())) {
    return make_error(Status::UnsupportedAlgorithm, "kunci RSA harus 3072 bit dan e=65537");
  }
  EvpMdCtx ctx = make_md_ctx();
  EVP_PKEY_CTX* pctx = nullptr;  // milik ctx; jangan di-free sendiri
  if (!ctx || EVP_DigestSignInit(ctx.get(), &pctx, EVP_sha256(), nullptr, key.get()) != 1 ||
      !apply_pss(pctx)) {
    return make_error(Status::InputError, "RSA-PSS sign init gagal: " + openssl_error());
  }
  Bytes sig(kRsaPssSigSize);
  std::size_t len = sig.size();
  if (EVP_DigestSign(ctx.get(), sig.data(), &len, message.data(), message.size()) != 1 ||
      len != kRsaPssSigSize) {
    return make_error(Status::InputError, "RSA-PSS sign gagal: " + openssl_error());
  }
  return sig;
}

bool rsa_pss_verify(const PublicKey& key, ByteView message, ByteView signature) {
  if (key.algorithm() != Algorithm::RsaPss) return false;
  if (signature.size() != kRsaPssSigSize) return false;
  if (!rsa_pss_profile_ok(key.get())) return false;
  EvpMdCtx ctx = make_md_ctx();
  EVP_PKEY_CTX* pctx = nullptr;
  if (!ctx || EVP_DigestVerifyInit(ctx.get(), &pctx, EVP_sha256(), nullptr, key.get()) != 1 ||
      !apply_pss(pctx)) {
    ERR_clear_error();
    return false;
  }
  const bool ok = EVP_DigestVerify(ctx.get(), signature.data(), signature.size(), message.data(),
                                   message.size()) == 1;
  ERR_clear_error();
  return ok;
}

}  // namespace sister_sign::crypto
