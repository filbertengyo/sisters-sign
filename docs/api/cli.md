# Referensi CLI {#cli}

[TOC]

```
sister-sign <command> [options]
```

Semua flag berbentuk `-nama nilai` atau `-nama=nilai` (`--nama` juga diterima). CLI tidak pernah
membaca stdin, tidak memakai prompt, dan tidak butuh TTY: argumen yang kurang atau salah langsung
menghasilkan pesan yang menyebut nama flag-nya dan exit 2. Flag tidak dikenal, flag ganda, dan
argumen posisional juga exit 2.

| Flag global | Keluaran |
|---|---|
| `-help` | usage ke stdout, exit 0 (juga `<command> -help`) |
| `-version` | `sister-sign <versi>` ke stdout, mis. `sister-sign 0.1.0` |

Tipe nilai flag di tabel bawah:

| Tipe | Arti |
|---|---|
| *path* | path berkas di sistem berkas (relatif terhadap direktori kerja) |
| *package* | string, pola `^[a-z0-9][a-z0-9._-]{0,63}$` |
| *version* | string, pola `^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$` |
| *algorithm* | salah satu `ed25519`, `ecdsa-p256-sha256`, `rsa-pss-sha256` |
| *keyid* | 64 karakter hex huruf kecil: `hex(SHA-256(DER SPKI pubkey))` |
| *bool* | flag tanpa nilai |

## Exit code dan status {#cli_status}

| Exit | Status | Arti |
|---|---|---|
| 0 | `OK` | sukses |
| 2 | `INPUT_ERROR` | argumen salah/kurang, berkas tidak ada/tidak terbaca, berkas keluaran sudah ada |
| 1 | `FORMAT_ERROR` | bundle, manifest (tidak kanonik), atau trust store tidak sah |
| 1 | `UNSUPPORTED_ALGORITHM` | algoritma di manifest atau kunci di luar tiga profil |
| 1 | `KEY_NOT_TRUSTED` | keyid tidak ada di trust store, tidak diizinkan untuk package, atau profil berbeda |
| 1 | `INVALID_SIGNATURE` | signature tidak cocok dengan manifest |
| 1 | `METADATA_MISMATCH` | package/version/nama berkas berbeda dari yang diharapkan |
| 1 | `ARTIFACT_MISMATCH` | ukuran atau SHA-256 artefak berbeda dari manifest |

`verify` berhenti di pemeriksaan pertama yang gagal, dengan urutan seperti tabel di atas (lihat
sister_sign::verifier::verify()). Status yang sama dipakai API C++ (sister_sign::Status).

## keygen {#cli_keygen}

Buat pasangan kunci baru.

```
sister-sign keygen -algorithm <algorithm> -out <prefix> [-force]
```

| Flag | Tipe | Wajib | Keterangan |
|---|---|---|---|
| `-algorithm` | *algorithm* | ya | profil kunci |
| `-out` | *path* (prefix) | ya | menulis `<prefix>.key.pem` dan `<prefix>.pub.pem` |
| `-force` | *bool* | tidak | timpa berkas yang sudah ada (tanpa ini: exit 2) |

**Keluaran.** Berkas `<prefix>.key.pem`: privkey PKCS#8 PEM tanpa enkripsi, mode 0600.
Berkas `<prefix>.pub.pem`: pubkey SPKI PEM, mode 0644. Stdout:

```
algorithm: ed25519
private key: app-key.key.pem
public key: app-key.pub.pem
keyid: 9a0a6912fffa349eed2c7a0c6fe72bc4f34225d128a6096d72aa79019a5d7d30
```

**Exit.** 0 sukses; 2 bila algoritma tidak dikenal, berkas sudah ada tanpa `-force`, atau
berkas tidak bisa ditulis.

@snippet cli_quickstart.sh keygen

## trust add | list | remove {#cli_trust}

Kelola trust store: daftar pubkey yang dipercaya beserta package yang boleh ditandatanganinya.
Ini satu-satunya cara menambah kepercayaan; `verify` tidak pernah mengambil pubkey dari bundle.
Setiap perubahan ditulis atomic (temp file, fsync, rename).

```
sister-sign trust add    -store <path> -key <path> -package <package>
sister-sign trust list   -store <path>
sister-sign trust remove -store <path> -keyid <keyid>
```

| Aksi | Flag | Tipe | Keterangan |
|---|---|---|---|
| `add` | `-store` | *path* | trust store (dibuat bila belum ada) |
| | `-key` | *path* | pubkey SPKI PEM yang dipercaya |
| | `-package` | *package* | package yang boleh ditandatangani kunci ini |
| `list` | `-store` | *path* | trust store |
| `remove` | `-store` | *path* | trust store |
| | `-keyid` | *keyid* | kunci yang dihapus (seluruh entrinya) |

**Keluaran.** `add`: berkas store diperbarui; stdout
`trusted <keyid> (<algorithm>) for package <package>`. Menambah kunci yang sama untuk package
lain menambah package ke entri yang sama; menambah ulang yang persis sama tidak mengubah apa pun.
`list`: tabel `KEYID ALGORITHM PACKAGES` ke stdout. `remove`: berkas store diperbarui.

**Exit.** 0 sukses; 2 untuk semua kegagalan: berkas tidak ada/tidak terbaca, isi store tidak
sah, pubkey tidak sah atau di luar profil, package di luar pola, atau keyid tidak ditemukan
(`remove`). Hanya `verify` (dan `sbom verify`/`check`) yang memakai exit 1 untuk penolakan.

@snippet cli_quickstart.sh trust

```
trusted 9a0a6912fffa349eed2c7a0c6fe72bc4f34225d128a6096d72aa79019a5d7d30 (ed25519) for package demo
KEYID                                                            ALGORITHM   PACKAGES
9a0a6912fffa349eed2c7a0c6fe72bc4f34225d128a6096d72aa79019a5d7d30  ed25519     demo
```

## sign {#cli_sign}

Tandatangani artefak dan tulis bundle.

```
sister-sign sign -file <path> -package <package> -version <version> -key <path> -out <path>
```

| Flag | Tipe | Wajib | Keterangan |
|---|---|---|---|
| `-file` | *path* | ya | artefak; basename-nya harus berpola `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$` |
| `-package` | *package* | ya | nama package |
| `-version` | *version* | ya | versi package |
| `-key` | *path* | ya | privkey PKCS#8 PEM; algoritma diturunkan dari kunci |
| `-out` | *path* | ya | berkas bundle keluaran |

**Proses.** Hitung ukuran dan SHA-256 artefak, bangun manifest kanonik M (@ref formats_manifest),
tandatangani byte M apa adanya, lalu tulis bundle (@ref formats_bundle). Signature diverifikasi
sendiri sebelum bundle ditulis.

**Keluaran.** Berkas bundle; stdout `signed <nama> (<n> bytes)`, `algorithm:`, `keyid:`,
`bundle:`.

**Exit.** 0 sukses; 2 untuk semua kegagalan (berkas tidak ada, kunci rusak atau di luar profil,
metadata di luar pola, keluaran tidak bisa ditulis).

@snippet cli_quickstart.sh sign

## verify {#cli_verify}

Verifikasi artefak terhadap bundle dan trust store.

```
sister-sign verify -file <path> -bundle <path> -trust-store <path> -package <package> -version <version> [-json]
```

| Flag | Tipe | Wajib | Keterangan |
|---|---|---|---|
| `-file` | *path* | ya | artefak yang diverifikasi (harus berkas biasa) |
| `-bundle` | *path* | ya | bundle dari `sign` |
| `-trust-store` | *path* | ya | trust store tepercaya milik pemakai |
| `-package` | *package* | ya | package yang **diharapkan** pemakai |
| `-version` | *version* | ya | versi yang **diharapkan** pemakai |
| `-json` | *bool* | tidak | cetak hasil sebagai satu objek JSON ke stdout |

**Keluaran tanpa `-json`.** OK: stdout `OK: <package> <version> (<algorithm>, keyid <keyid>)`.
Gagal: stderr `<STATUS>: <pesan>`.

**Keluaran dengan `-json`.** Stdout selalu tepat satu baris JSON (juga saat gagal); saat gagal
ringkasan `<STATUS>: <pesan>` juga ditulis ke stderr. Field (Tabel 2.9):

| Field | Tipe JSON | Keterangan |
|---|---|---|
| `valid` | boolean | `true` hanya bila `status` = `OK` |
| `status` | string | salah satu status di @ref cli_status |
| `message` | string | penjelasan untuk manusia |
| `algorithm` | string \| null | dari manifest; `null` bila manifest belum terbaca (`INPUT_ERROR`, `FORMAT_ERROR`) |
| `keyid` | string \| null | dari manifest (64 hex); `null` seperti di atas |
| `package` | string \| null | dari manifest; `null` seperti di atas |
| `version` | string \| null | dari manifest; `null` seperti di atas |

Saat gagal, `algorithm`/`keyid`/`package`/`version` hanya penjelasan (isi manifest yang ditolak),
bukan data tepercaya.

**Exit.** Lihat @ref cli_status. Pakai exit code (bukan isi stdout) untuk memutuskan apakah
pipeline boleh lanjut.

@snippet cli_quickstart.sh verify

```json
{"valid":true,"status":"OK","message":"OK","algorithm":"ed25519","keyid":"9a0a6912fffa349eed2c7a0c6fe72bc4f34225d128a6096d72aa79019a5d7d30","package":"demo","version":"1.0.0"}
```

Contoh penolakan:

@snippet cli_quickstart.sh verify-fail

```
{"valid":false,"status":"METADATA_MISMATCH","message":"version tidak cocok: manifest '1.0.0', diharapkan '2.0.0'","algorithm":"ed25519","keyid":"9a0a6912fffa349eed2c7a0c6fe72bc4f34225d128a6096d72aa79019a5d7d30","package":"demo","version":"1.0.0"}
exit 1
{"valid":false,"status":"INPUT_ERROR","message":"artefak tidak ada atau bukan berkas biasa: hilang.bin","algorithm":null,"keyid":null,"package":null,"version":null}
exit 2
```

## sbom sign | verify | check {#cli_sbom}

Bonus: SBOM CycloneDX JSON yang ditandatangani dengan format bundle yang sama dan mengikat
SHA-256 artefak rilis.

```
sister-sign sbom sign   -sbom <path> -package <package> -version <version> -key <path> -out <path>
sister-sign sbom verify -sbom <path> -bundle <path> -trust-store <path> -package <package> -version <version> [-json]
sister-sign sbom check  -sbom <path> -file <path> [-json]
```

| Aksi | Flag | Tipe | Keterangan |
|---|---|---|---|
| `sign` | `-sbom` | *path* | SBOM CycloneDX JSON; divalidasi dulu |
| | `-package` | *package* | harus sama dengan `metadata.component.name` |
| | `-version` | *version* | harus sama dengan `metadata.component.version` |
| | `-key` | *path* | privkey PKCS#8 PEM |
| | `-out` | *path* | bundle SBOM keluaran |
| `verify` | `-sbom`, `-bundle`, `-trust-store`, `-package`, `-version`, `-json` | | seperti `verify`, atas berkas SBOM, ditambah validasi isi SBOM |
| `check` | `-sbom` | *path* | SBOM yang sudah lolos `sbom verify` |
| | `-file` | *path* | artefak rilis; SHA-256-nya harus tercatat di SBOM |
| | `-json` | *bool* | hasil sebagai JSON seperti `verify -json` |

**Exit.** Sama dengan `verify` (@ref cli_status); artefak yang tidak cocok dengan SBOM =
`ARTIFACT_MISMATCH` (1).
