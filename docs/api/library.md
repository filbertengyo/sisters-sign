# API C++ {#library}

[TOC]

Semua logika ada di library statis `core` (`src/`); executable `sister-sign` hanya membungkusnya
(sister_sign::cli::run()). Pakai dari CMake dengan `target_link_libraries(<target> PRIVATE core)`;
include relatif terhadap `src/`, mis. `#include "verify/verify.hpp"`.

## Modul {#library_modules}

Panah hanya turun: modul hanya memakai modul di bawahnya.

| Modul | Namespace | Header | Isi |
|---|---|---|---|
| CLI | sister_sign::cli | cli/cli.hpp, cli/args.hpp | dispatcher subcommand, parser flag, JSON hasil verify |
| Verify | sister_sign::verifier | verify/verify.hpp | Algoritma 2: verifikasi artefak (urutan pemeriksaan tetap) |
| Trust | sister_sign::trust | trust/trust.hpp | trust store: parse strict, lookup, add/remove, simpan atomic |
| Bundle | sister_sign::bundle | bundle/bundle.hpp | baca/tulis bundle (manifest + signature, base64 strict) |
| Manifest | sister_sign::manifest | manifest/manifest.hpp | serialisasi kanonik + parse strict, validator field, nama algoritma |
| Crypto | sister_sign::crypto | crypto/crypto.hpp, crypto/keyio.hpp, crypto/keys.hpp, crypto/raii.hpp | sign/verify 3 profil, keyid, keygen, PEM, RAII OpenSSL |
| Util | sister_sign::util, sister_sign | util/result.hpp, util/hash.hpp, util/hex.hpp, util/base64.hpp, util/json_scan.hpp | Status/Outcome, SHA-256, hex, base64 strict, pemeriksa JSON |

## Konvensi error {#library_errors}

Tidak ada exception yang melewati batas modul. Fungsi yang bisa gagal mengembalikan
sister_sign::Outcome<T> (`std::expected<T, Error>`); sister_sign::Error membawa
sister_sign::Status dan pesan (tidak pernah isi privkey). Pemetaan status ke exit code proses
hanya ada di sister_sign::exit_code().

```cpp
auto key = sister_sign::crypto::read_private_key("app-key.key.pem");
if (!key) {
  std::cerr << sister_sign::to_string(key.error().status) << ": " << key.error().message << "\n";
  return sister_sign::exit_code(key.error().status);
}
sister_sign::crypto::Algorithm alg = key->algorithm();  // profil diturunkan dari kunci
```

Fungsi verifikasi kripto tingkat rendah (sister_sign::crypto::verify()) mengembalikan `bool`
saja; alasan penolakan ditentukan pemanggil. sister_sign::verifier::verify() mengembalikan
sister_sign::Result lengkap (status, pesan, metadata) seperti `verify -json`.

## Contoh: sign lalu verify {#library_example}

Contoh lengkap ada di `docs/api/examples/sign_verify.cpp` dan dijalankan oleh `ctest`
(`api_example_sign_verify`). Langkah yang sama dengan `sister-sign sign`:

@snippet sign_verify.cpp sign

Trust store dibuat terpisah oleh pemakai (setara `sister-sign trust add`):

@snippet sign_verify.cpp trust

Verifikasi (setara `sister-sign verify -json`); artefak yang diubah setelah sign ditolak dengan
`ARTIFACT_MISMATCH`:

@snippet sign_verify.cpp verify

Keluaran:

```
{"valid":true,"status":"OK","message":"OK","algorithm":"ed25519","keyid":"...","package":"demo","version":"1.0.0"}
{"valid":false,"status":"ARTIFACT_MISMATCH","message":"SHA-256 artefak tidak cocok","algorithm":"ed25519","keyid":"...","package":"demo","version":"1.0.0"}
```
