#pragma once
// RAII untuk objek OpenSSL + buffer rahasia (T06). Semua alokasi/pembebasan OpenSSL di kode
// produksi wajib lewat tipe di sini; jangan memanggil `*_free` manual.
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace sister_sign::crypto {

// ---- smart pointer untuk objek OpenSSL ---------------------------------------------------------
struct EvpPkeyDeleter {
  void operator()(EVP_PKEY* p) const noexcept { EVP_PKEY_free(p); }
};
struct EvpPkeyCtxDeleter {
  void operator()(EVP_PKEY_CTX* p) const noexcept { EVP_PKEY_CTX_free(p); }
};
struct EvpMdCtxDeleter {
  void operator()(EVP_MD_CTX* p) const noexcept { EVP_MD_CTX_free(p); }
};
struct EcdsaSigDeleter {
  void operator()(ECDSA_SIG* p) const noexcept { ECDSA_SIG_free(p); }
};
// BIGNUM yang berisi bahan rahasia dibersihkan (BN_clear_free) sebelum dibebaskan.
struct BignumDeleter {
  void operator()(BIGNUM* p) const noexcept { BN_clear_free(p); }
};
struct BioDeleter {
  void operator()(BIO* p) const noexcept { BIO_free_all(p); }
};

using EvpPkey = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using EvpPkeyCtx = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;
using EvpMdCtx = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;
using EcdsaSig = std::unique_ptr<ECDSA_SIG, EcdsaSigDeleter>;
using Bignum = std::unique_ptr<BIGNUM, BignumDeleter>;
using Bio = std::unique_ptr<BIO, BioDeleter>;

// Pembuat yang mengembalikan wrapper kosong (nullptr) bila OpenSSL gagal alokasi.
inline EvpMdCtx make_md_ctx() { return EvpMdCtx(EVP_MD_CTX_new()); }
inline EvpPkeyCtx make_pkey_ctx(EVP_PKEY* pkey) {
  return EvpPkeyCtx(EVP_PKEY_CTX_new(pkey, nullptr));
}
inline EvpPkeyCtx make_pkey_ctx(const char* algorithm) {
  return EvpPkeyCtx(EVP_PKEY_CTX_new_from_name(nullptr, algorithm, nullptr));
}
inline EcdsaSig make_ecdsa_sig() { return EcdsaSig(ECDSA_SIG_new()); }
inline Bignum make_bignum() { return Bignum(BN_new()); }
inline Bio make_mem_bio() { return Bio(BIO_new(BIO_s_mem())); }

// ---- buffer rahasia ----------------------------------------------------------------------------
// Hapus isi memori dengan OPENSSL_cleanse (tidak dioptimasi hilang oleh compiler).
void secure_cleanse(void* data, std::size_t size) noexcept;

// Buffer ukuran tetap yang dibersihkan sebelum dibebaskan. Allocator hanya untuk pengujian.
template <class Alloc = std::allocator<std::uint8_t>>
class BasicSecureBuffer {
 public:
  BasicSecureBuffer() = default;
  explicit BasicSecureBuffer(std::size_t size, const Alloc& alloc = Alloc())
      : data_(size, 0, alloc) {}
  explicit BasicSecureBuffer(std::span<const std::uint8_t> bytes, const Alloc& alloc = Alloc())
      : data_(bytes.begin(), bytes.end(), alloc) {}

  BasicSecureBuffer(const BasicSecureBuffer&) = delete;
  BasicSecureBuffer& operator=(const BasicSecureBuffer&) = delete;
  BasicSecureBuffer(BasicSecureBuffer&& other) noexcept : data_(std::move(other.data_)) {
    other.data_.clear();
  }
  BasicSecureBuffer& operator=(BasicSecureBuffer&& other) noexcept {
    if (this != &other) {
      wipe();
      data_ = std::move(other.data_);
      other.data_.clear();
    }
    return *this;
  }
  ~BasicSecureBuffer() { wipe(); }

  std::uint8_t* data() noexcept { return data_.data(); }
  const std::uint8_t* data() const noexcept { return data_.data(); }
  std::size_t size() const noexcept { return data_.size(); }
  bool empty() const noexcept { return data_.empty(); }
  std::span<std::uint8_t> span() noexcept { return {data_.data(), data_.size()}; }
  std::span<const std::uint8_t> span() const noexcept { return {data_.data(), data_.size()}; }

  // Nolkan isi (ukuran tetap).
  void wipe() noexcept { secure_cleanse(data_.data(), data_.size()); }

 private:
  std::vector<std::uint8_t, Alloc> data_;
};

using SecureBuffer = BasicSecureBuffer<>;

// ---- error OpenSSL -----------------------------------------------------------------------------
// Ambil dan kosongkan antrean error OpenSSL jadi satu baris ("lib:reason; ..."). Hanya memuat kode
// error baku; teks data tambahan OpenSSL sengaja dibuang supaya tidak membawa isi kunci.
std::string openssl_error();

}  // namespace sister_sign::crypto
