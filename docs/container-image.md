# Image container sister-sign (T25)

Image berisi binary `sister-sign` saja, dipakai pipeline (T26) sebagai kakas tanpa build dari source.

- [`Dockerfile`](../Dockerfile): multi-stage.
  - **build**: `debian:trixie` + `g++-14` (14.2) + CMake 3.31.6 + `libssl-dev` (**OpenSSL 3.5.7**), semua dari apt Debian. Build Release.
  - **runtime**: `debian:trixie-slim` + `libssl3t64` (**OpenSSL 3.5.7**) + `libstdc++6`, user non-root `10001:10001`, `WORKDIR /work`, `ENTRYPOINT ["/usr/local/bin/sister-sign"]`, `CMD ["-help"]`. Build gagal kalau `libssl3t64` < 3.5.
  - Kedua base image dipin by digest. Build dan runtime sama-sama trixie, jadi `libstdc++`/OpenSSL di kedua stage cocok.
- [`.dockerignore`](../.dockerignore): allowlist (`CMakeLists.txt`, `include/`, `src/`, `tests/`, `bench/`). `tests/fixtures/` dan semua `*.pem`/`*.key`/`*.der`/`*.p8`/`*.p12`/`*.pfx` dikecualikan, jadi kunci tidak pernah masuk build context.
- [`.github/workflows/build-image.yml`](../.github/workflows/build-image.yml): push tag `v*` memicu build `linux/amd64`, push ke GHCR, pencatatan digest, lalu pull anonim by digest. Di PR yang mengubah build, image hanya di-build dan dicek (tanpa push).
- [`ci/check-image.sh`](../ci/check-image.sh): cek yang sama untuk CI dan lokal, termasuk roundtrip fungsional `keygen → trust add → sign → verify -json` untuk ketiga profil.
- Pemakai image: [`release-pipeline.yml`](../.github/workflows/release-pipeline.yml) (T26), lihat [`ci/README.md`](../ci/README.md).

## Build & jalankan lokal

```sh
docker build -t sister-sign:dev .
docker run --rm sister-sign:dev -version            # -> sister-sign 0.1.0

# pola pemakaian di pipeline: tanpa jaringan, uid pemanggil, input read-only
docker run --rm --network none --user "$(id -u):$(id -g)" \
  -v "$PWD:/work:ro" sister-sign:dev -version

# semua cek T25 (exit != 0 kalau ada yang gagal)
bash ci/check-image.sh sister-sign:dev 0.1.0
```

Output yang ditulis (`sign -out`, `trust add`) butuh mount kedua yang **tidak** `:ro`, misalnya `-v "$PWD/out:/out"`. Privkey jangan pernah di-`COPY` ke image. Mount saat runtime saja (lihat T26).

## Hasil cek lokal (15 Nov 2026, Docker 28.5.1, linux/amd64)

Dijalankan dengan `bash ci/check-image.sh sister-sign:dev 0.1.0` (exit 0) pada image hasil `docker build` dari `main` (`3bf4ae0`) ditambah perubahan T25/T26/T29/T37 yang belum di-commit.

| Cek | Hasil |
|---|---|
| `docker run --rm <img> -version` | `sister-sign 0.1.0`, exit 0 |
| `--network none --user 4242:4242 --read-only --cap-drop ALL --security-opt no-new-privileges` | jalan, exit 0 |
| `--user $(id -u):$(id -g)` + `-v ...:/work:ro` | input terbaca; tulis ke `/work` (bahkan sebagai root) ditolak |
| Roundtrip `ed25519`, `ecdsa-p256-sha256`, `rsa-pss-sha256` | `keygen` → `trust add` → `sign` (artefak `:ro`) → `verify -json`: exit 0, `{"valid":true,"status":"OK",...}` |
| Artefak diubah 1 byte (nama dan ukuran sama), 3 profil | `verify -json`: exit 1, `{"valid":false,"status":"ARTIFACT_MISMATCH",...}` |
| User default | `10001:10001` (bukan root) |
| `docker history --no-trunc` | tidak ada `PRIVATE KEY` / `.pem` / `.key` / `.p12` / `.pfx` |
| Filesystem image | tidak ada PEM private key (berkas teks) maupun berkas berekstensi kunci |
| OpenSSL di image | `libssl3t64 3.5.7-1~deb13u3` (Debian 13.7) |
| `libstdc++6` di image | `14.2.0-19` |
| Dependensi dinamis binary | `libcrypto.so.3`, `libstdc++.so.6`, `libgcc_s.so.1`, `libm`, `libc` |
| Binary | `/usr/local/bin/sister-sign`, 470 304 byte (stripped; termasuk subperintah bonus `sbom`) |
| Ukuran image | **≈ 78.0 MiB** tak terkompresi (`docker export` = 81 770 496 byte); **≈ 28.7 MiB** terkompresi / ukuran pull (`docker image inspect` `Size` = 30 086 155 byte) |

Lapisan image (`docker history`): base `debian:trixie-slim` 87.7 MB, `apt-get install libssl3t64 libstdc++6` + user 77.8 kB (keduanya sudah ada di base, jadi hampir tidak menambah), `COPY sister-sign` 487 kB, `WORKDIR /work` 8 kB. Tidak ada layer yang berisi kunci.

`ci/check-image.sh` juga sudah diuji negatif. Ia gagal (exit 1) untuk image yang berisi PEM key dengan nama berkas samaran, yang `COPY *.pem`, dan yang jalan sebagai root.

Selain itu `ci/test-pipeline.sh` (T26) memakai image yang sama lewat registry lokal, jadi jalur *pull by digest → sign → verify → deploy* juga teruji di setiap PR yang menyentuh build atau `ci/`.

## Rilis ke GHCR

Langkah ini butuh akses tulis ke repo dan admin package, jadi dijalankan oleh pemegang rilis (C).

1. Pastikan versi di `src/util/version.cpp` dan `project(... VERSION ...)` sama dengan tag. Workflow memberi warning kalau `-version` tidak cocok dengan tag.
2. Pastikan tiga secret kunci demo sudah diset (lihat [`ci/README.md`](../ci/README.md#secret)). Tanpa secret, job `sign` di release pipeline gagal dan draft release tidak dibuat.
3. `git tag v0.1.0 && git push origin v0.1.0`. Workflow men-tag image dengan `0.1.0`, `0.1`, `sha-<commit>`, dan `latest`.
4. **Rilis pertama**: package GHCR baru biasanya privat. Kalau begitu, job `anonymous pull by digest` gagal dengan pesan error yang jelas. Buka *github.com/filbertengyo → Packages → sisters-sign → Package settings → Danger Zone → Change visibility → Public*, lalu *Re-run failed jobs*. Kalau push ditolak, cek *Settings → Actions → General → Workflow permissions* (read and write) dan, untuk package yang sudah ada, *Package settings → Manage Actions access* (repo `sisters-sign` dengan role *Write*).
5. Setelah `anonymous pull by digest` hijau, `release pipeline` jalan otomatis terhadap digest baru dan membuat **draft** GitHub Release (lihat [`docs/release.md`](release.md)).
6. Salin digest dari job summary atau artefak `image-digest` ke tabel di bawah, ke tabel di [`README.md`](../README.md#versi--tag--digest), dan ke [`ci/image-ref.txt`](../ci/image-ref.txt) (dipakai release pipeline saat dijalankan manual).

Cek publik dari mesin yang **tidak** login ke GHCR:

```sh
docker logout ghcr.io
docker pull ghcr.io/filbertengyo/sisters-sign@sha256:<digest>
docker image inspect --format '{{join .RepoDigests "\n"}}' ghcr.io/filbertengyo/sisters-sign@sha256:<digest>
# harus memuat ghcr.io/filbertengyo/sisters-sign@sha256:<digest> yang sama
```

Pipeline (T26) WAJIB pull **by digest**, bukan by tag (`ci/resolve-image.sh` menolak tag):

```sh
docker pull ghcr.io/filbertengyo/sisters-sign@sha256:<digest>
```

## Versi ↔ tag ↔ digest

| Versi | Git tag | Image tag | Digest (`linux/amd64`) |
|---|---|---|---|
| 0.1.0 | `v0.1.0` (belum di-push) | `ghcr.io/filbertengyo/sisters-sign:0.1.0` | belum dirilis: isi dari job summary `build-image` |

Digest build lokal tidak dicatat di sini karena build tidak bit-reproducible (timestamp layer), sehingga digest GHCR pasti berbeda. Yang berlaku hanya digest dari workflow.

## Catatan

- **OpenSSL 3.5 di semua tempat**: image (trixie, 3.5.7), CI (`ci.yml` job build/sanitizer jalan di container `debian:trixie`), dan `find_package(OpenSSL 3.5 REQUIRED)` di `CMakeLists.txt`. Konsekuensinya:
  - ECDSA deterministik (RFC 6979, butuh OpenSSL ≥ 3.2) tersedia di image maupun CI. Ini relevan untuk U14 (T22) dan asumsi #5 di rencana kerja.
  - Configure gagal di OpenSSL < 3.5 dengan pesan `Found unsuitable version "3.0.13", but required is at least "3.5"`. Ubuntu 24.04 (termasuk WSL default) masih 3.0.13, jadi build lokal harus di Debian trixie atau di container (`docker run -v "$PWD:/src" debian:trixie ...`).
  - Tetap pakai one-shot untuk Ed25519 dan set salt RSA-PSS secara eksplisit (lihat [spike-c](spike-c.md)).
- Privkey tidak pernah masuk build context (`.dockerignore`), layer, maupun filesystem image. Di pipeline, privkey hanya di-mount `:ro` saat `sign` dari temp file di runner, lalu dihapus (T26).
