# tests/integration: uji integrasi CI/CD C01-C05 (T27)

Bukti bahwa image rilis bisa dipakai di runner bersih dan bahwa **keputusan verify menentukan
apakah deploy jalan** (spek Bagian 2.9, Tabel 2.15). Semua perintah jalan di container image
rilis **by digest** lewat skrip pipeline yang sama dengan
[`release-pipeline.yml`](../../.github/workflows/release-pipeline.yml) (`ci/*.sh`); program tidak
dipasang dari source.

| ID | Skenario | Diharapkan |
|---|---|---|
| C01 | sign + verify + deploy (berkas penanda), **x3 algoritma** | exit 0, `OK`, `deploy/DEPLOYED` ada |
| C02 | ubah 1 byte artefak setelah sign (ukuran + nama tetap), ulangi verify | exit 1, `ARTIFACT_MISMATCH`, DEPLOYED tidak ada |
| C03 | trust store kosong; dan kunci yang sama tetapi hanya dipercaya untuk package lain | exit 1, `KEY_NOT_TRUSTED`, DEPLOYED tidak ada |
| C04 | path artefak tidak ada (bundle + trust store sah) | exit 2, `INPUT_ERROR`, DEPLOYED tidak ada |
| C05 | image dengan UID/GID runner, tanpa TTY, `--network none` | `docker inspect`: network `none`, user = `id -u:id -g`, Tty/OpenStdin `false`; berkas output milik UID/GID runner; parameter kurang -> exit 2 (bukan menunggu input) |

Aturan yang dipegang [`run.sh`](run.sh):

- **Direktori bersih per skenario.** `<out>/<ID>-<nama>/` dibuat baru (`mkdir` gagal kalau sudah
  ada), berisi salinan artefak rilis sendiri. Tidak ada penanda dari skenario lain yang terbawa.
- **Gerbang yang sama dengan pipeline.** `ci/verify-artifact.sh`, lalu `ci/deploy-marker.sh` hanya
  bila verify exit 0. Tidak ada `continue-on-error` atau `|| true` pada jalur itu.
- **Exit code asli dulu.** Skenario negatif dinilai dari exit code sister-sign
  (`verify/verify.json.exit`), lalu `status` di JSON, lalu ada/tidaknya `deploy/DEPLOYED`. Untuk
  C04, `ci/verify-artifact.sh` tidak lagi mengecek artefak sebelum container jalan, supaya exit 2
  berasal dari CLI dan bukan dari skrip pembungkus.
- **Privkey.** Kunci demo hanya dari env `DEMO_KEY_*` (secret). Tiap sign menulisnya ke temp file
  `0600` di luar output lalu menghapusnya. Output diaudit (`ci/audit-no-privkey.sh`).

Bukti per skenario: `result.txt` (diharapkan vs hasil), `commands.txt` (perintah `docker run`
persis), `verify/verify.json` + `.exit` + `.stderr`, `verify.log`, `deploy.log`, `deploy/` (hanya
C01), `tamper.txt` (C02), `inspect.txt` (C05). Ringkasan di `<out>/results.md` dan `<out>/image.txt`
(image, digest, versi, sha256 artefak, UID/GID runner, commit, run id).

## Menjalankan

**Bukti resmi** (image rilis di GHCR, kunci demo dari secret):
*Actions → integration → Run workflow* (input `image` = `<repo>@sha256:...`, kosong =
`ci/image-ref.txt`). Workflow ini juga jalan otomatis saat push tag `v*`, setelah image di-push
(`build-image.yml`, job `integration`). Workflow hijau berarti semua penolakan terbukti. Unduh
artefak `integration-results` (bukti) dan `integration-logs` (log job, sudah lolos audit privkey).

**Lokal / PR** (tanpa secret, image dibangun lokal, kunci sementara). Ini juga dijalankan di job
PR `build-image`. Ini **bukan** bukti C01 untuk laporan, karena image dibangun dari source:

```sh
docker run -d -p 5000:5000 --name registry registry:2
docker build -t sister-sign:dev .
bash tests/integration/selftest.sh sister-sign:dev localhost:5000 out/integration
```

Catatan: dengan **Docker rootless**, `--user $(id -u):$(id -g)` di container tidak sama dengan
user host, jadi bind mount tidak bisa ditulis dan cek kepemilikan C05 gagal. Itu memang perilaku
yang dideteksi C05. Runner GitHub (`ubuntu-24.04`) memakai Docker rootful.

## Hasil

### Workflow run resmi

> **Belum ada.** Isi setelah run `integration` terhadap image rilis: link run, image@digest, dan
> salin `results.md` dari artefak `integration-results` ke sini (atau ke lampiran laporan).

| | |
|---|---|
| Workflow run | _(link)_ |
| Image | _(ghcr.io/...@sha256:...)_ |
| Commit | _(sha)_ |

### Uji lokal (16 Nov 2026, bukan bukti resmi)

Docker 29.8.1 **rootless**, image dibangun lokal dan di-push ke `localhost:5055`, kunci sementara.
Agar bind mount bisa ditulis di Docker rootless, `id -u/-g` di-shim menjadi `0` (root container =
user host). Karena itu cek kepemilikan C05 gagal sesuai catatan di atas: berkas dimiliki
`1000:1000`, bukan `0:0`. Network/user/TTY/stdin dan "parameter kurang -> exit 2" lulus.

| ID | Skenario | Hasil |
|---|---|---|
| C01 | sign + verify + deploy (ed25519) | exit 0, `OK`, DEPLOYED ada: PASS |
| C01 | sign + verify + deploy (ecdsa-p256-sha256) | exit 0, `OK`, DEPLOYED ada: PASS |
| C01 | sign + verify + deploy (rsa-pss-sha256) | exit 0, `OK`, DEPLOYED ada: PASS |
| C02 | 1 byte diubah (offset 1: 69 -> 68, 470304 B, nama sama) | exit 1, `ARTIFACT_MISMATCH`, DEPLOYED tidak ada: PASS |
| C03 | trust store kosong | exit 1, `KEY_NOT_TRUSTED`, DEPLOYED tidak ada: PASS |
| C03 | kunci hanya dipercaya untuk `other-package` | exit 1, `KEY_NOT_TRUSTED`, DEPLOYED tidak ada: PASS |
| C04 | path artefak tidak ada | exit 2, `INPUT_ERROR`, DEPLOYED tidak ada: PASS |
| C05 | network none, tanpa TTY/stdin, exit 2 tanpa argumen | PASS; kepemilikan berkas: FAIL (Docker rootless, lihat atas) |
