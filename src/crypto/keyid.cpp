// keyid = hex_lower(SHA-256(DER SPKI)): identitas kunci publik yang tidak bergantung pada format
// PEM (line ending, lebar baris, spasi) karena dihitung dari DER hasil encode ulang OpenSSL.
#include <openssl/x509.h>

#include "crypto/crypto.hpp"
#include "crypto/keys.hpp"
#include "util/hash.hpp"
#include "util/hex.hpp"

namespace sister_sign::crypto {

Outcome<std::string> keyid(const PublicKey& key) {
  const int len = i2d_PUBKEY(key.get(), nullptr);
  if (len <= 0) return make_error(Status::InputError, "keyid: encode SPKI gagal");
  Bytes der(static_cast<std::size_t>(len));
  unsigned char* p = der.data();
  if (i2d_PUBKEY(key.get(), &p) != len) {
    return make_error(Status::InputError, "keyid: encode SPKI gagal");
  }
  auto digest = util::sha256(der);
  if (!digest) return std::unexpected(digest.error());
  return util::hex_lower(*digest);
}

}  // namespace sister_sign::crypto
