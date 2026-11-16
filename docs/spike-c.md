# Spike C: Ed25519 one-shot & parameter RSA-PSS

Kode: [`tests/spikes/ed_rsa_spike.cpp`](../tests/spikes/ed_rsa_spike.cpp), jalan lewat `ctest -R spike_c`.
Dipakai oleh implementasi Ed25519 dan RSA-PSS; temuan umum juga relevan untuk RAII OpenSSL, ECDSA P-256, dan I/O kunci.

## Ringkasan

| | Ed25519 | RSA-PSS 3072 |
|---|---|---|
| Init | `EVP_DigestSignInit(ctx, NULL, NULL /*md*/, NULL, key)` | `EVP_DigestSignInit(ctx, &pctx, EVP_sha256(), NULL, key)` |
| Parameter | tidak ada; md HARUS `NULL` (md lain ditolak saat init) | `EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING)`<br>`EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, 32)`<br>`EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha256())` |
| Sign | `EVP_DigestSign` satu panggilan, M apa adanya | `EVP_DigestSign` satu panggilan, M apa adanya (OpenSSL yang meng-hash, JANGAN pre-hash) |
| Verify | `EVP_DigestVerifyInit` + `EVP_DigestVerify` | `EVP_DigestVerifyInit` + parameter PSS yang SAMA + `EVP_DigestVerify` |
| Streaming (`*Update`/`*Final`) | DILARANG: Update gagal, Final crash di OpenSSL < 3.5 | jalan, tapi tidak dipakai (lihat rekomendasi) |
| Panjang sig | 64 byte (`EVP_PKEY_get_size` = 64) | 384 byte (`EVP_PKEY_get_size` = 384) |
| DER SPKI (`i2d_PUBKEY`) | 44 byte | 422 byte (OID rsaEncryption) |
| Sig berulang (U14) | identik (deterministik, RFC 8032) | BEDA tiap kali (salt acak), semua verify OK |

## Lingkungan uji

| Tempat | OpenSSL | Hasil `spike_c` |
|---|---|---|
| Windows, MinGW GCC 15.2 | 3.6.1 | 11/11 lulus |
| `debian:trixie`, g++-14, `-Werror` (= CI + image sekarang) | 3.5.7 | 11/11 lulus |
| `debian:trixie`, g++-14, ASAN + UBSAN | 3.5.7 | 11/11 lulus, tanpa temuan sanitizer |
| `ubuntu:24.04`, g++-14, `-Werror` dan ASAN + UBSAN (CI lama) | 3.0.13 | 11/11 lulus, tanpa temuan sanitizer |

Sejak `CMakeLists.txt` mewajibkan OpenSSL ≥ 3.5, CI dan image memakai Debian trixie (3.5.7). Baris 3.0.13 adalah hasil sebelum perubahan itu.

Perilaku streaming Ed25519 lintas versi (tabel di bawah) diukur dengan probe C kecil di luar repo: `EVP_DigestSignInit` lalu `*Update`/`*Final`, dijalankan di tiap image. Crash-nya bisa direproduksi dengan spike ini sendiri (`SPIKE_C_UNSAFE=1`).

## Ed25519

### Snippet final

```cpp
// sign: one-shot, md = NULL, pesan M apa adanya
MdCtxPtr ctx(EVP_MD_CTX_new());
if (!ctx || EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, key) != 1) return error;
Bytes sig(EVP_PKEY_get_size(key));          // 64
std::size_t len = sig.size();
if (EVP_DigestSign(ctx.get(), sig.data(), &len, msg.data(), msg.size()) != 1) return error;
sig.resize(len);

// verify: cek panjang dulu, hanya return 1 yang dianggap valid
if (sig.size() != 64) return false;
MdCtxPtr vctx(EVP_MD_CTX_new());
if (!vctx || EVP_DigestVerifyInit(vctx.get(), nullptr, nullptr, nullptr, pub) != 1) return false;
const bool ok = EVP_DigestVerify(vctx.get(), sig.data(), sig.size(), msg.data(), msg.size()) == 1;
ERR_clear_error();
return ok;
```

### Temuan

1. `EVP_DigestSignUpdate` / `EVP_DigestVerifyUpdate` pada ctx Ed25519 return 0 di semua versi yang diuji, dan error tercatat di antrean OpenSSL.
2. `EVP_DigestSignFinal` / `EVP_DigestVerifyFinal` pada ctx Ed25519 **SEGFAULT** di OpenSSL < 3.5. Ini bukan sekadar return error. Hasil probe:

   | OpenSSL | Image | `*Update` | `*Final` |
   |---|---|---|---|
   | 3.0.13 | `ubuntu:24.04` | 0 | SIGSEGV |
   | 3.0.22 | `debian:bookworm-slim` | 0 | SIGSEGV |
   | 3.1.8 | `alpine:3.19` | 0 | SIGSEGV |
   | 3.3.7 | `alpine:3.20` | 0 | SIGSEGV |
   | 3.5.7 | `debian:trixie-slim` (CI + image) | 0 | 0 |
   | 3.6.1 | MinGW lokal | 0 | 0 |

   Di spike, pemanggilan `*Final` dilewati kalau OpenSSL < 3.5. Untuk mereproduksi crash: `SPIKE_C_UNSAFE=1 ./build/spike_c`.
3. `EVP_DigestSignInit` dengan md `EVP_sha256()` ditolak; md wajib `NULL`.
4. Pesan kosong dengan `msg.data() == nullptr` (vector kosong) aman untuk sign dan verify. Pesan 1 MiB juga OK.
5. Sig 63/65/0 byte, flip 1 bit sig/pesan, dan kunci lain semuanya ditolak OpenSSL. Tetap cek panjang == 64 secara eksplisit sebelum memanggil OpenSSL.
6. Memakai ulang ctx setelah one-shot berbeda antar versi: `EVP_DigestSign` kedua return 1 di 3.0.13, tapi 0 di 3.6.1. Aturannya: satu `EVP_MD_CTX` per operasi.

## RSA-PSS 3072

### Snippet final

```cpp
// parameter PSS dipasang di pctx milik ctx (JANGAN di-free sendiri), SAMA untuk sign & verify
bool apply_pss(EVP_PKEY_CTX* pctx) {
  return EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) > 0 &&
         EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, 32) > 0 &&
         EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha256()) > 0;
}

// sign
MdCtxPtr ctx(EVP_MD_CTX_new());
EVP_PKEY_CTX* pctx = nullptr;
if (!ctx || EVP_DigestSignInit(ctx.get(), &pctx, EVP_sha256(), nullptr, key) != 1 ||
    !apply_pss(pctx)) return error;
Bytes sig(EVP_PKEY_get_size(key));          // 384
std::size_t len = sig.size();
if (EVP_DigestSign(ctx.get(), sig.data(), &len, msg.data(), msg.size()) != 1) return error;
sig.resize(len);

// verify
if (sig.size() != 384) return false;
MdCtxPtr vctx(EVP_MD_CTX_new());
EVP_PKEY_CTX* vpctx = nullptr;
if (!vctx || EVP_DigestVerifyInit(vctx.get(), &vpctx, EVP_sha256(), nullptr, pub) != 1 ||
    !apply_pss(vpctx)) { ERR_clear_error(); return false; }
const bool ok = EVP_DigestVerify(vctx.get(), sig.data(), sig.size(), msg.data(), msg.size()) == 1;
ERR_clear_error();
return ok;

// cek profil kunci (bisa dari pubkey saja, mis. dari trust store)
bool rsa_profile_ok(EVP_PKEY* key) {
  BIGNUM* e = nullptr;  // bungkus dengan BnPtr dari raii.hpp
  bool ok = EVP_PKEY_get_base_id(key) == EVP_PKEY_RSA && EVP_PKEY_get_bits(key) == 3072 &&
            EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_E, &e) == 1 && BN_is_word(e, RSA_F4);
  BN_free(e);
  return ok;
}
```

Keygen yang diuji (untuk I/O kunci): `EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr)`, `EVP_PKEY_keygen_init`, `EVP_PKEY_CTX_set_rsa_keygen_bits(3072)`, `EVP_PKEY_CTX_set1_rsa_keygen_pubexp(e=65537)`, `EVP_PKEY_generate`. Butuh sekitar 1 detik per kunci, jadi test cukup memakai satu kunci fixture.

### Temuan

1. **Salt default berbeda antar versi OpenSSL.** Kalau `set_rsa_pss_saltlen` lupa dipanggil, salt menjadi 350 byte (maksimum) di 3.0 dan 32 byte di ≥ 3.1. Dua-duanya terbukti di spike. CI dan image sekarang ≥ 3.5, jadi default-nya kebetulan 32, tapi profil tidak boleh bergantung pada default versi. **Wajib set 32 secara eksplisit.**
2. **Verifier juga harus set salt 32 secara eksplisit, bukan `RSA_PSS_SALTLEN_AUTO`.** AUTO menerima sig dengan salt berapa pun (termasuk 350), sehingga sig di luar profil ikut lolos. Dengan salt 32 eksplisit, sig ber-salt 20, 64, atau maksimum ditolak. `RSA_PSS_SALTLEN_DIGEST` (-1) setara 32 untuk SHA-256.
3. **MGF1 default = md signature (SHA-256).** Tetap set eksplisit supaya jelas. Verify dengan MGF1-SHA1 atau SHA384 ditolak, membuktikan sig memakai MGF1-SHA256.
4. Verify tanpa `set_rsa_padding(PSS)` (default PKCS#1 v1.5) ditolak.
5. Dua sign pada pesan yang sama menghasilkan sig BERBEDA, dan dua-duanya verify.
6. Sig 383/385 byte, flip 1 bit sig/pesan, dan kunci lain semuanya ditolak OpenSSL. Tetap cek panjang == 384 secara eksplisit.
7. Kunci dari keygen `"RSA"` bertipe `EVP_PKEY_RSA` dengan OID SPKI rsaEncryption, bukan `EVP_PKEY_RSA_PSS`. Kunci bertipe RSASSA-PSS punya SPKI berbeda, jadi keyid-nya juga berbeda. Usul untuk I/O kunci: profil `rsa-pss` hanya menerima `EVP_PKEY_RSA` 3072/e=65537 dan menolak tipe `RSA_PSS` supaya keyid stabil. Perlu disepakati.
8. Kunci 2048 bit atau e=3 terdeteksi lewat `EVP_PKEY_get_bits` / `OSSL_PKEY_PARAM_RSA_E`.

## Rekomendasi untuk RAII OpenSSL, Ed25519, ECDSA, dan RSA-PSS

- **Pakai one-shot `EVP_DigestSign` / `EVP_DigestVerify` untuk KETIGA algoritma.** M (manifest) kecil dan sudah ada di memori. Satu jalur kode berarti tidak ada risiko streaming Ed25519 tidak sengaja terpanggil. ECDSA dan RSA-PSS juga jalan dengan one-shot.
- Ukuran buffer sig ambil dari `EVP_PKEY_get_size(key)`, lalu `resize(len)` setelah sign. Untuk ECDSA ini ukuran DER maksimum, sebelum konversi ke r||s (lihat spike B).
- Hanya return `== 1` yang berarti sukses. `EVP_DigestVerify` return 0 untuk sig salah dan < 0 untuk error lain.
- Setelah kegagalan yang diharapkan (verify gagal), panggil `ERR_clear_error()`. `openssl_error()` di RAII OpenSSL (`crypto/raii.hpp`) sebaiknya menguras antrean (`ERR_get_error` sampai 0) supaya pesan error berikutnya tidak tercampur.
- `EVP_PKEY_CTX*` yang dikembalikan `EVP_DigestSignInit`/`EVP_DigestVerifyInit` dimiliki `EVP_MD_CTX`. JANGAN dibungkus RAII atau di-free sendiri.
- Satu `EVP_MD_CTX` per operasi; jangan dipakai ulang.

## Cek silang dengan CLI `openssl`

```sh
mkdir -p /tmp/spike-c && SPIKE_C_DUMP=/tmp/spike-c ./build/spike_c
cd /tmp/spike-c
openssl pkeyutl -verify -pubin -inkey ed25519.pub.pem -rawin -in msg.bin -sigfile ed25519.sig
# -> Signature Verified Successfully
openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 \
  -sigopt rsa_mgf1_md:sha256 -verify rsa.pub.pem -signature rsa_pss.sig msg.bin
# -> Verified OK
openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:20 \
  -verify rsa.pub.pem -signature rsa_pss.sig msg.bin
# -> Verification failure ... salt length check failed: expected: 20 retrieved: 32
```

Sudah dijalankan dengan CLI OpenSSL 3.2.4 (build terpisah dari library yang dipakai spike). Ketiga hasil sesuai harapan, dan `msg.bin` yang ditambah 1 byte ditolak oleh `pkeyutl -verify`.

## Catatan lingkungan build (untuk semua)

- glaze v8.4.0 butuh **CMake ≥ 3.31**. `cmake` dari apt di Ubuntu 24.04 (3.28) dan Debian bookworm (3.25) terlalu tua dan gagal saat configure. CI sekarang memakai container `debian:trixie` (CMake 3.31.6 dari apt). Di WSL Ubuntu 24.04, pakai `pip install "cmake>=3.31"` atau binary dari Kitware. Root `CMakeLists.txt` sudah `cmake_minimum_required(VERSION 3.31)`, jadi CMake yang terlalu tua langsung gagal dengan pesan yang jelas.
- Build Windows/MinGW juga jalan (`-DOPENSSL_ROOT_DIR=<mingw>/opt`). DLL `libstdc++`/`libcrypto` dari MinGW harus lebih dulu di `PATH` daripada milik Git (`/mingw64/bin`). Kalau tidak, test exe gagal dengan `0xc0000139`.
- `CMakeLists.txt` mewajibkan **OpenSSL ≥ 3.5** (`find_package(OpenSSL 3.5 REQUIRED)`). Ubuntu 24.04 / WSL default (3.0.13) tidak lagi bisa configure; build di Debian trixie atau container `debian:trixie`.
