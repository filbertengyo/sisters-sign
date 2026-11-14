# Spike B: ECDSA DER <-> r||s

Tujuan: membuktikan konversi signature ECDSA P-256 antara format DER (keluaran OpenSSL) dan
`r||s` 64 byte (format di bundle) benar, sebelum dipakai `crypto::sign/verify`.
Implementasi: `src/crypto/ecdsa.cpp`; bukti: `tests/unit/crypto_ecdsa_test.cpp`.

## Dua format

| | DER (`ECDSA-Sig-Value`) | `r‖s` (format kita) |
|---|---|---|
| Struktur | `SEQUENCE { INTEGER r, INTEGER s }` | `r` 32 byte big-endian + `s` 32 byte big-endian |
| Panjang | **variabel** (umumnya 70-72 byte, bisa 68-72) | **tetap 64 byte** |
| Sumber variasi | INTEGER minimal: nol di depan dibuang; bila bit tertinggi 1 ditambah `0x00` | `BN_bn2binpad` mengisi nol di depan sampai 32 byte |
| Dipakai oleh | OpenSSL CLI, X.509, TLS | bundle `signature_b64`, ukuran sig di laporan |

## Konversi

- **DER -> r‖s:** `d2i_ECDSA_SIG` (tolak byte sisa di belakang) -> `ECDSA_SIG_get0` ->
  `BN_bn2binpad(r, out, 32)` dan `BN_bn2binpad(s, out+32, 32)`. Gagal bila r atau s > 32 byte.
- **r‖s -> DER:** `BN_bin2bn` untuk r dan s -> tolak nol -> `ECDSA_SIG_set0` (mengambil alih
  BIGNUM) -> `i2d_ECDSA_SIG`.
- **Verify:** panjang harus tepat 64 (DER mentah ikut ditolak karena panjangnya bukan 64), r dan s
  harus di `[1, n-1]` (n = order kurva dari `OSSL_PKEY_PARAM_EC_ORDER`), lalu dirakit ulang ke DER dan
  diverifikasi `EVP_DigestVerify` dengan SHA-256. Low-S tidak diwajibkan.

## Bukti

- 1000 signature (nonce acak dari OpenSSL): semuanya roundtrip DER -> r‖s -> verify OK dan
  r‖s -> DER identik dengan DER asal (DER kanonik).
- Panjang DER bervariasi di antara signature-signature itu (test memastikan ada lebih dari satu
  panjang berbeda), sedangkan `r‖s` selalu 64 byte.
- Cek silang: signature kita dikonversi balik ke DER lalu lolos `openssl dgst -sha256 -verify`
  (dilewati otomatis bila CLI `openssl` tidak ada; dicakup lagi di interop T28).

## Nonce

`ecdsa_sign` memakai parameter `nonce-type=1` (RFC 6979, OpenSSL >= 3.2), jadi pesan sama ->
signature identik. Tanpa parameter ini OpenSSL memakai nonce acak (signature berbeda tiap kali).
Ini yang dipakai analisis U14 dan demo nonce reuse (T30).
