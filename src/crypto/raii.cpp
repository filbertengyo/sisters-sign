#include "crypto/raii.hpp"

#include <openssl/crypto.h>
#include <openssl/err.h>

namespace sister_sign::crypto {

void secure_cleanse(void* data, std::size_t size) noexcept {
  if (data != nullptr && size != 0) OPENSSL_cleanse(data, size);
}

std::string openssl_error() {
  std::string out;
  while (unsigned long code = ERR_get_error()) {
    char buf[256];
    ERR_error_string_n(code, buf, sizeof(buf));
    if (!out.empty()) out += "; ";
    out += buf;
  }
  return out.empty() ? "unknown OpenSSL error" : out;
}

}  // namespace sister_sign::crypto
