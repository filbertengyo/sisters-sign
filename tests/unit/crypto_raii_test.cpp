#include <doctest/doctest.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <type_traits>

#include "crypto/raii.hpp"

using namespace sister_sign::crypto;

namespace {

// Allocator pengintai: saat deallocate, catat apakah seluruh blok sudah nol.
struct Spy {
  bool all_zero = false;
  bool freed = false;
};

template <class T>
struct SpyAllocator {
  using value_type = T;
  using propagate_on_container_move_assignment = std::true_type;
  Spy* spy;
  explicit SpyAllocator(Spy* s) : spy(s) {}
  template <class U>
  SpyAllocator(const SpyAllocator<U>& o) : spy(o.spy) {}
  T* allocate(std::size_t n) { return std::allocator<T>().allocate(n); }
  void deallocate(T* p, std::size_t n) {
    spy->freed = true;
    spy->all_zero = true;
    for (std::size_t i = 0; i < n; ++i)
      if (p[i] != 0) spy->all_zero = false;
    std::allocator<T>().deallocate(p, n);
  }
  template <class U>
  bool operator==(const SpyAllocator<U>& o) const {
    return spy == o.spy;
  }
};

using SpyBuffer = BasicSecureBuffer<SpyAllocator<std::uint8_t>>;

}  // namespace

TEST_CASE("each wrapper type can be created and destroyed") {
  CHECK(make_md_ctx() != nullptr);
  CHECK(make_ecdsa_sig() != nullptr);
  CHECK(make_bignum() != nullptr);
  CHECK(make_mem_bio() != nullptr);
  EvpPkeyCtx kctx = make_pkey_ctx("ED25519");
  REQUIRE(kctx != nullptr);
  REQUIRE(EVP_PKEY_keygen_init(kctx.get()) == 1);
  EVP_PKEY* raw = nullptr;
  REQUIRE(EVP_PKEY_keygen(kctx.get(), &raw) == 1);
  EvpPkey key(raw);
  CHECK(key != nullptr);
  CHECK(make_pkey_ctx(key.get()) != nullptr);
}

TEST_CASE("wrappers release on early exit via exception (ASAN/LSAN catches leaks)") {
  auto act = [] {
    EvpMdCtx md = make_md_ctx();
    EcdsaSig sig = make_ecdsa_sig();
    Bignum bn = make_bignum();
    Bio bio = make_mem_bio();
    SecureBuffer buf(64);
    throw std::runtime_error("boom");
  };
  CHECK_THROWS_AS(act(), std::runtime_error);
}

TEST_CASE("empty wrappers are safe") {
  EvpPkey k;
  EvpPkeyCtx c;
  EvpMdCtx m;
  EcdsaSig s;
  Bignum b;
  Bio o;
  CHECK(k == nullptr);
}

TEST_CASE("SecureBuffer is zeroed after destruction") {
  Spy spy;
  {
    SpyBuffer buf(32, SpyAllocator<std::uint8_t>(&spy));
    for (std::size_t i = 0; i < buf.size(); ++i) buf.data()[i] = 0xAB;
    CHECK(buf.size() == 32);
  }
  CHECK(spy.freed);
  CHECK(spy.all_zero);
}

TEST_CASE("SecureBuffer: copy from span, move, wipe") {
  const std::uint8_t src[4] = {1, 2, 3, 4};
  SecureBuffer a{std::span<const std::uint8_t>(src)};
  REQUIRE(a.size() == 4);
  CHECK(a.data()[3] == 4);

  SecureBuffer b = std::move(a);
  CHECK(a.empty());
  CHECK(b.size() == 4);

  const std::uint8_t* p = b.data();
  b.wipe();
  for (int i = 0; i < 4; ++i) CHECK(p[i] == 0);
}

TEST_CASE("SecureBuffer move-assign wipes the replaced content") {
  Spy spy_a, spy_b;
  SpyBuffer a(8, SpyAllocator<std::uint8_t>(&spy_a));
  for (std::size_t i = 0; i < a.size(); ++i) a.data()[i] = 0xCD;
  SpyBuffer b(8, SpyAllocator<std::uint8_t>(&spy_b));
  a = std::move(b);  // blok lama milik a dibebaskan lewat operator= vector; harus sudah nol
  CHECK(a.size() == 8);
  CHECK(spy_a.freed);
  CHECK(spy_a.all_zero);
}

TEST_CASE("openssl_error drains the queue and reports only error codes") {
  ERR_clear_error();
  // DER sampah memicu error di OpenSSL.
  const unsigned char junk[] = {0x30, 0x03, 0x01, 0x02, 0x03};
  const unsigned char* p = junk;
  EvpPkey k(d2i_AutoPrivateKey(nullptr, &p, sizeof(junk)));
  CHECK(k == nullptr);
  std::string msg = openssl_error();
  CHECK_FALSE(msg.empty());
  CHECK(msg != "unknown OpenSSL error");
  CHECK(ERR_peek_error() == 0);  // antrean sudah kosong
  CHECK(openssl_error() == "unknown OpenSSL error");
}

TEST_CASE("secure_cleanse tolerates null and zero size") {
  secure_cleanse(nullptr, 10);
  std::uint8_t x = 7;
  secure_cleanse(&x, 0);
  CHECK(x == 7);
  secure_cleanse(&x, 1);
  CHECK(x == 0);
}
