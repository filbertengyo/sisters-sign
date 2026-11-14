#pragma once
#include <array>
#include <cstdint>
#include <memory>

#include "util/bytes.hpp"
#include "util/result.hpp"

namespace sister_sign::util {

using Sha256Digest = std::array<std::uint8_t, 32>;

// Satu kali jalan.
Outcome<Sha256Digest> sha256(ByteView data);

// Streaming untuk berkas besar: update() berkali-kali lalu finish() sekali.
class Sha256 {
 public:
  Sha256();
  ~Sha256();
  Sha256(Sha256&&) noexcept;
  Sha256& operator=(Sha256&&) noexcept;
  Sha256(const Sha256&) = delete;
  Sha256& operator=(const Sha256&) = delete;

  Outcome<void> update(ByteView data);
  Outcome<Sha256Digest> finish();

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace sister_sign::util
