# Analisis U14: tanda tangan berulang atas manifest yang identik

Skenario U14 (Tabel 2.11): tandatangani manifest yang identik dua kali dengan kunci yang sama,
bandingkan kedua tanda tangan, jelaskan hasilnya berdasarkan algoritma dan mekanisme randomness/nonce,
dan pastikan kedua bundle berhasil diverifikasi.

Kasus: `tests/e2e/cases/sign-verify-roundtrip/U14-{ed25519,ecdsa,rsa}-repeat-sign.sh`. Jalankan:

```bash
cmake --build build && bash tests/e2e/run.sh build/sister-sign tests/e2e/cases build/e2e-results
# atau satu kasus saja: salin berkasnya ke direktori kosong lalu jalankan run.sh pada direktori itu
```

Tiap kasus membuat kunci baru, menandatangani artefak yang sama dua kali (`a.bundle.json`,
`b.bundle.json`), mengekstrak byte manifest dan signature dari keduanya, lalu membandingkan.

## Hasil

| Profil | Manifest | Signature (a vs b) | Kedua bundle verify |
|---|---|---|---|
| `ed25519` | identik | **identik** | OK |
| `ecdsa-p256-sha256` | identik | **identik** | OK |
| `rsa-pss-sha256` | identik | **berbeda** | OK |

Lingkungan pengukuran: OpenSSL 3.6.3 (WSL, GCC 15.2). CI memakai `debian:trixie` dengan OpenSSL
>= 3.5. Perilaku di bawah berlaku untuk OpenSSL >= 3.2 (ECDSA deterministik butuh parameter
`nonce-type`, tersedia sejak 3.2). Catat versi OpenSSL yang dipakai saat menjalankan ulang.

## Penjelasan per algoritma

### Ed25519: identik (deterministik menurut desain)

Ed25519 (RFC 8032, PureEdDSA) tidak memakai bilangan acak saat menandatangani. Nonce `r` dihitung
sebagai `r = SHA-512(prefix || M) mod L`, dengan `prefix` diturunkan dari kunci privat. Jadi pesan
dan kunci yang sama selalu menghasilkan `R` dan `S` yang sama, dan tanda tangan 64 byte-nya identik.
Tidak ada sumber randomness yang bisa salah dipakai pada saat sign.

### ECDSA P-256: identik karena nonce deterministik (RFC 6979)

ECDSA standar membutuhkan nonce `k` yang unik dan tidak dapat ditebak untuk setiap tanda tangan;
bila `k` acak, dua signature atas pesan yang sama berbeda. Implementasi ini sengaja meminta nonce
deterministik RFC 6979 lewat parameter `nonce-type=1` pada `EVP_PKEY_CTX` di
`src/crypto/ecdsa.cpp`. `k` diturunkan dengan HMAC-DRBG dari kunci privat dan hash pesan
(`SHA-256(M)`), sehingga `(r, s)` identik untuk pesan dan kunci yang sama. Spek mengizinkan keduanya
(nonce dari CSPRNG atau RFC 6979, Tabel 2.1 dan "Ketentuan Implementasi Algoritma").

Catatan:

- Tanpa `nonce-type=1`, OpenSSL memakai nonce acak (campuran CSPRNG dan kunci privat) dan hasilnya
  berbeda tiap kali. Hasil identik di atas karena parameter itu diset, bukan karena sifat bawaan ECDSA.
- Di OpenSSL < 3.2 parameter ini tidak ada; hasilnya akan berbeda. Versi OpenSSL wajib dicatat.
- Kedua signature berformat `r || s` 64 byte (hasil DER dikonversi), jadi perbandingan byte langsung
  valid. Low-S tidak dinormalisasi, sesuai spek.
- Keamanan: yang berbahaya adalah *nonce yang dipakai ulang atau bias*, bukan signature yang
  identik. Nonce deterministik menghilangkan risiko ini selama implementasinya benar (demo reuse nonce
  direncanakan di T30).

### RSA-PSS (3072 bit, SHA-256, MGF1-SHA-256, salt 32 byte): berbeda (salt acak)

PSS menyisipkan salt acak sepanjang 32 byte ke dalam pesan yang di-encode sebelum operasi RSA:
`EM = maskedDB || H || 0xBC` dengan `H = SHA-256(0x00..00 || SHA-256(M) || salt)`. Salt diambil dari
CSPRNG pada setiap sign, sehingga signature 384 byte berbeda walaupun `M` dan kunci sama. Verifier
tidak perlu mengetahui salt sebelumnya: salt dipulihkan dari `EM` saat verifikasi, jadi kedua
signature yang berbeda sama-sama valid. Ini sifat yang diinginkan dari PSS (keamanan bukti
reduksi; probabilistik), berbeda dengan RSASSA-PKCS1-v1_5 yang deterministik.

## Kesimpulan

- Ed25519 dan ECDSA (RFC 6979) deterministik: signature berulang atas manifest yang sama identik.
  Konsekuensinya, dua rilis dengan manifest identik menghasilkan bundle yang identik (bagus untuk
  build yang dapat direproduksi) tetapi juga berarti signature tidak dapat dipakai untuk mengetahui
  apakah sebuah rilis ditandatangani ulang.
- RSA-PSS probabilistik: signature berbeda tiap sign, namun semuanya valid. Perbedaan bukan tanda
  kesalahan.
- Identik atau tidak, kebenaran ditentukan oleh verifikasi: kedua bundle pada ketiga profil lolos
  (`status=OK`, `exit=0`), dan manifest (`M`) selalu identik byte-per-byte karena serialisasinya
  kanonik.
