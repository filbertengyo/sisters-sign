# sister-sign: dokumentasi API {#mainpage}

**sister-sign** menandatangani dan memverifikasi artefak rilis perangkat lunak. Penerbit membuat
*bundle* (manifest kanonik + signature) untuk sebuah artefak; pemakai memverifikasi artefak
terhadap bundle dan *trust store* miliknya sendiri sebelum memakai atau men-deploy artefak itu.

Tiga profil algoritma didukung:

| Nama (`-algorithm`, manifest) | Algoritma | Ukuran signature |
|---|---|---|
| `ed25519` | Ed25519 murni (RFC 8032) | 64 byte |
| `ecdsa-p256-sha256` | ECDSA P-256 + SHA-256, signature `r‖s` (bukan DER) | 64 byte |
| `rsa-pss-sha256` | RSA 3072, e=65537, PSS SHA-256, MGF1-SHA-256, salt 32 byte | 384 byte |

Dokumentasi ini memuat dua API:

| Halaman | Isi | Untuk |
|---|---|---|
| @ref cli | Perintah `keygen`, `trust`, `sign`, `verify`, `sbom`: flag (masukan) beserta tipe, keluaran, exit code, JSON `verify -json`, contoh | pemakai CLI / image container dan pipeline CI/CD |
| @ref formats | Format berkas: manifest, bundle, trust store, kunci; field beserta tipe dan aturannya | implementasi lain yang ingin membuat/membaca bundle (lihat juga docs/interop.md) |
| @ref library | API C++ (library `core`): modul, konvensi error, contoh sign + verify | pengembang yang memakai atau mengubah kode |

Referensi lengkap per fungsi (parameter, tipe, nilai kembali, error) ada di menu **Namespaces**
dan **Files**, dibangkitkan dari komentar di header `src/`.

## Mulai cepat

Semua contoh di dokumentasi ini diambil langsung dari berkas yang dijalankan oleh `ctest`
(`docs/api/examples/`), jadi perintah dan kode yang tertulis memang berjalan.

@snippet cli_quickstart.sh keygen
@snippet cli_quickstart.sh trust
@snippet cli_quickstart.sh sign
@snippet cli_quickstart.sh verify

Contoh keluaran `verify -json` (keyid berbeda tiap kunci):

```json
{"valid":true,"status":"OK","message":"OK","algorithm":"ed25519","keyid":"9a0a6912fffa349eed2c7a0c6fe72bc4f34225d128a6096d72aa79019a5d7d30","package":"demo","version":"1.0.0"}
```

Dengan image container (tanpa jaringan, UID/GID pemanggil, input read-only):

```sh
docker run --rm --network none --user "$(id -u):$(id -g)" \
  -v "$PWD:/work:ro" ghcr.io/filbertengyo/sisters-sign@sha256:<digest> \
  verify -file /work/app.bin -bundle /work/app.bundle.json -trust-store /work/trust.json \
  -package demo -version 1.0.0 -json
```

## Membangun dari source

```sh
cmake -B build && cmake --build build && ctest --test-dir build
```

Butuh GCC >= 14, CMake >= 3.31, OpenSSL >= 3.5. Dokumentasi ini sendiri dibangun dengan
`bash docs/api/build.sh` (Doxygen + tema doxygen-awesome-css).
