#include "crypto/ed25519.hpp"

#include <openssl/err.h>

namespace sister_sign::crypto {

Outcome<Bytes> ed25519_sign(const PrivateKey& key, ByteView message) {
  if (key.algorithm() != Algorithm::Ed25519) {
    return make_error(Status::UnsupportedAlgorithm, "kunci bukan Ed25519");
  }
  EvpMdCtx ctx = make_md_ctx();
  if (!ctx || EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, key.get()) != 1) {
    return make_error(Status::InputError, "Ed25519 sign init gagal: " + openssl_error());
  }
  Bytes sig(kEd25519SigSize);
  std::size_t len = sig.size();
  // Satu panggilan; EVP_DigestSignUpdate tidak boleh dipakai untuk Ed25519.
  if (EVP_DigestSign(ctx.get(), sig.data(), &len, message.data(), message.size()) != 1 ||
      len != kEd25519SigSize) {
    return make_error(Status::InputError, "Ed25519 sign gagal: " + openssl_error());
  }
  return sig;
}

bool ed25519_verify(const PublicKey& key, ByteView message, ByteView signature) {
  if (key.algorithm() != Algorithm::Ed25519) return false;
  if (signature.size() != kEd25519SigSize) return false;
  EvpMdCtx ctx = make_md_ctx();
  if (!ctx || EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, key.get()) != 1) {
    ERR_clear_error();
    return false;
  }
  // 1 = valid; 0 atau negatif = tolak.
  const bool ok = EVP_DigestVerify(ctx.get(), signature.data(), signature.size(), message.data(),
                                   message.size()) == 1;
  ERR_clear_error();
  return ok;
}

}  // namespace sister_sign::crypto
