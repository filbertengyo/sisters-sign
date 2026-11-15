# Harness e2e

Menjalankan kasus uji lewat biner `sister-sign` di direktori kerja yang bersih, menyimpan bukti per
kasus, dan membuat tabel markdown untuk laporan.

```sh
# semua kasus di tests/e2e/cases, hasil ke direktori sembarang
bash tests/e2e/run.sh build/sister-sign tests/e2e/cases build/e2e-results

# lewat CMake (hasil ke tests/results, termasuk results.md untuk laporan)
cmake --build build --target e2e_report

# bukti bahwa harness sendiri benar (kasus gagal sengaja terdeteksi gagal)
ctest --test-dir build -R e2e
```

## Menambah kasus

Satu kasus = satu berkas kecil `tests/e2e/cases/<ID>-<nama>.sh`:

```bash
DESC="artefak diubah setelah sign -> ARTIFACT_MISMATCH"
EXPECT_EXIT=1                     # wajib
EXPECT_STATUS=ARTIFACT_MISMATCH   # opsional
run() {
  setup_signed ed25519            # kunci k.*, app.bin, t.json, app.bundle.json
  make_file app.bin "diubah"
  verify_std                      # perintah TERAKHIR (sis ...) yang dinilai
}
```

Variabel harapan (semua opsional kecuali `EXPECT_EXIT`): `EXPECT_STATUS`, `EXPECT_STDOUT_CONTAINS`,
`EXPECT_STDERR_CONTAINS`, `EXPECT_STDOUT_EMPTY=1`, `EXPECT_JSON_LINE=1` (stdout = satu objek JSON
satu baris).

Helper (lihat `lib.sh`): `sis` (jalankan sister-sign, dicatat), `must` (persiapan; gagal = ERROR),
`make_file`, `make_bytes`, `gen_key`, `trust_add`, `sign_ok`, `setup_signed`, `verify_std`.
Hanya pemanggilan `sis` terakhir yang dinilai; panggilan persiapan bungkus dengan `must`.

## Alat bantu untuk kasus yang memanipulasi bundle

CLI `sign` selalu membangun manifest kanonik sendiri, jadi kasus yang butuh masukan rusak memakai
`forge` (`tests/tools/forge.cpp`, di-build bersama proyek dan hanya untuk test; runner mencarinya di
direktori yang sama dengan biner `sister-sign`):

```bash
forge sign-manifest <key.pem> <manifest-file> <out-bundle>   # tanda tangani byte berkas apa adanya
forge extract-manifest  <bundle> <out>                       # byte manifest M
forge extract-signature <bundle> <out>                       # byte signature
forge replace-manifest  <bundle> <manifest-file> <out>       # ganti M, signature lama tetap
forge flip-sig-bit      <bundle> <out> [bit]                 # balik satu bit signature
forge reformat          <bundle> <out>                       # urutan field + whitespace berbeda
```

Helper tambahan di `lib.sh`: `forge`, `manifest_text`, `sha256_of`, `file_size`, `make_binary`,
`make_empty`, dan pemeriksaan di luar perintah yang dinilai: `check_same A B desk`,
`check_differs A B desk`, `check_eq X Y desk`. Semua `check_*` harus PASS; hasilnya masuk
`checks.txt` dan tampil di tabel sebagai `checks=ok/total`. `gen_key` menyimpan keyid terakhir di
`$KEYID`.

Kasus boleh diletakkan di subdirektori (runner mencari `*.sh` secara rekursif); ID = nama berkas.

## Cakupan skenario spek (Tabel 2.11)

| Folder | Skenario |
|---|---|
| `cases/sign-verify-roundtrip/` | U01 (3 algoritma x teks/biner/kosong), U14 (3 algoritma, sign dua kali) |
| `cases/tamper-and-trust/` | U02-U09 (Ed25519) |
| `cases/strict-format-and-algorithm/` | U10 (7 kondisi terpisah), U11 (2 nilai), U12, U13 (Ed25519) |

## Hasil

Per kasus di `<hasil>/<ID>/`: `commands.txt` (semua perintah), `expected.txt`, `actual.txt`,
`stdout.txt`, `stderr.txt`, `inputs.txt` (hash berkas kerja) dan `inputs/` (salinan berkas kecil,
tanpa privkey). Ringkasan: `results.tsv` dan `results.md`. Status: PASS, FAIL (hasil tidak sesuai
harapan), ERROR (persiapan gagal atau kasus tidak lengkap).
