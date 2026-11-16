# Format berkas {#formats}

[TOC]

Semua berkas JSON adalah UTF-8 tanpa BOM. Key ganda dan field tambahan selalu ditolak
(`FORMAT_ERROR`), karena parser JSON biasa diam-diam membuang salah satu key ganda
(sister_sign::util::check_json_no_duplicate_keys()).

## Manifest {#formats_manifest}

Metadata artefak yang ditandatangani. Yang ditandatangani adalah **byte** manifest (M) apa adanya,
tanpa pre-hash. Karena itu manifest hanya punya satu representasi byte yang sah (kanonik), dan
verifikasi menolak manifest yang tidak kanonik meskipun isinya sama.

```json
{"schema":"minisign-manifest/v1","package":"demo","version":"1.0.0","algorithm":"ed25519","keyid":"9a0a6912fffa349eed2c7a0c6fe72bc4f34225d128a6096d72aa79019a5d7d30","artifact":{"name":"app.bin","size":17,"sha256":"89998300f7bfaf485f04ef0072206a8bdc95439f9f6a5421851760ce7593e85c"}}
```

| Field | Tipe JSON | Aturan |
|---|---|---|
| `schema` | string | tepat `"minisign-manifest/v1"` |
| `package` | string | `^[a-z0-9][a-z0-9._-]{0,63}$` |
| `version` | string | `^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$` |
| `algorithm` | string | `ed25519`, `ecdsa-p256-sha256`, atau `rsa-pss-sha256` (lainnya: `UNSUPPORTED_ALGORITHM`) |
| `keyid` | string | 64 hex huruf kecil, `hex(SHA-256(DER SPKI pubkey))` |
| `artifact.name` | string | basename artefak, `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$` |
| `artifact.size` | integer | ukuran artefak dalam byte, 0 sampai 2^53 - 1, desimal polos |
| `artifact.sha256` | string | SHA-256 artefak, 64 hex huruf kecil |

Bentuk kanonik: urutan field persis seperti tabel, tanpa spasi atau newline, string ASCII tanpa
escape, maksimum 16 KiB. API: sister_sign::manifest::serialize(), sister_sign::manifest::parse().

## Bundle {#formats_bundle}

Keluaran `sign`: membungkus byte M dan signature tanpa mengubah M.

```json
{"schema":"minisign-bundle/v1","manifest_b64":"eyJzY2hlbWEiOiJtaW5p...","signature_b64":"XInBXo7iYHOg..."}
```

| Field | Tipe JSON | Aturan |
|---|---|---|
| `schema` | string | tepat `"minisign-bundle/v1"` |
| `manifest_b64` | string | base64 (RFC 4648, alfabet standar, padding wajib, kanonik) dari byte M |
| `signature_b64` | string | base64 signature atas byte M |

Format signature per algoritma:

| Algoritma | Signature | Catatan |
|---|---|---|
| `ed25519` | 64 byte | Ed25519 murni atas M |
| `ecdsa-p256-sha256` | 64 byte `r‖s`, masing-masing 32 byte big-endian | DER (format bawaan OpenSSL) **ditolak** (`INVALID_SIGNATURE`) |
| `rsa-pss-sha256` | 384 byte | PSS, hash SHA-256, MGF1-SHA-256, salt tepat 32 byte |

Urutan field dan whitespace bundle bebas; maksimum 64 KiB. API: sister_sign::bundle::write(),
sister_sign::bundle::read().

## Trust store {#formats_trust}

Daftar kunci tepercaya milik pemakai. Dikelola dengan `trust add|list|remove`; store kosong
berarti tidak percaya siapa pun.

```json
{
   "schema": "minisign-trust/v1",
   "keys": [
      {
         "keyid": "9a0a6912fffa349eed2c7a0c6fe72bc4f34225d128a6096d72aa79019a5d7d30",
         "algorithm": "ed25519",
         "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAMMNnV0S+iCiHsb7vi06p6uAZqF2n1zbLeCqxeW/lhg8=\n-----END PUBLIC KEY-----\n",
         "packages": [
            "demo"
         ]
      }
   ]
}
```

| Field | Tipe JSON | Aturan |
|---|---|---|
| `schema` | string | tepat `"minisign-trust/v1"` |
| `keys` | array | boleh kosong; keyid tidak boleh ganda |
| `keys[].keyid` | string | harus sama dengan keyid dari `public_key_pem` |
| `keys[].algorithm` | string | harus sama dengan profil `public_key_pem` |
| `keys[].public_key_pem` | string | pubkey SPKI PEM dalam profil |
| `keys[].packages` | array of string | tidak kosong, unik, pola *package*, tanpa wildcard |

Saat `verify`, kunci dicari dengan keyid dari manifest, harus diizinkan untuk package yang
*diharapkan pemakai* (`-package`), dan profilnya harus sama dengan `algorithm` di manifest. API:
sister_sign::trust::TrustStore.

## Berkas kunci {#formats_keys}

| Berkas | Format | Keterangan |
|---|---|---|
| privkey | PEM `PRIVATE KEY` (PKCS#8), tanpa enkripsi | label lain (`ENCRYPTED PRIVATE KEY`, `RSA PRIVATE KEY`, ...) ditolak; ditulis `keygen` dengan mode 0600 |
| pubkey | PEM `PUBLIC KEY` (SPKI) | dipakai `trust add` |

Profil yang diterima: RSA 3072 bit dengan e = 65537, EC P-256 (named curve), Ed25519. Kunci lain
(RSA 2048, P-384, Ed448, ...) ditolak dengan `UNSUPPORTED_ALGORITHM`. API:
sister_sign::crypto::read_private_key(), sister_sign::crypto::read_public_key().
