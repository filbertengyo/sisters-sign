#include "util/hash.hpp"

#include <openssl/evp.h>

#include "crypto/raii.hpp"

namespace sister_sign::util {

struct Sha256::Impl {
  crypto::EvpMdCtx ctx = crypto::make_md_ctx();
  bool ready = false;
  bool finished = false;
};

Sha256::Sha256() : impl_(std::make_unique<Impl>()) {
  impl_->ready = impl_->ctx && EVP_DigestInit_ex(impl_->ctx.get(), EVP_sha256(), nullptr) == 1;
}
Sha256::~Sha256() = default;
Sha256::Sha256(Sha256&&) noexcept = default;
Sha256& Sha256::operator=(Sha256&&) noexcept = default;

Outcome<void> Sha256::update(ByteView data) {
  if (!impl_ || !impl_->ready || impl_->finished) {
    return make_error(Status::InputError, "sha256: konteks tidak siap");
  }
  if (!data.empty() && EVP_DigestUpdate(impl_->ctx.get(), data.data(), data.size()) != 1) {
    return make_error(Status::InputError, "sha256: update gagal");
  }
  return {};
}

Outcome<Sha256Digest> Sha256::finish() {
  if (!impl_ || !impl_->ready || impl_->finished) {
    return make_error(Status::InputError, "sha256: konteks tidak siap");
  }
  Sha256Digest out{};
  unsigned int len = 0;
  if (EVP_DigestFinal_ex(impl_->ctx.get(), out.data(), &len) != 1 || len != out.size()) {
    return make_error(Status::InputError, "sha256: finalisasi gagal");
  }
  impl_->finished = true;
  return out;
}

Outcome<Sha256Digest> sha256(ByteView data) {
  Sha256 h;
  if (auto r = h.update(data); !r) return std::unexpected(r.error());
  return h.finish();
}

}  // namespace sister_sign::util
