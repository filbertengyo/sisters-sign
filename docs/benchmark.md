# Benchmark sister-sign (T29)

Metode, cara menjalankan, dan format berkas: [`bench/README.md`](../bench/README.md). Data mentah (setiap sampel) dan ringkasan: [`bench/results/run1/`](../bench/results/run1), [`bench/results/run2/`](../bench/results/run2), perbandingan: [`bench/results/compare.md`](../bench/results/compare.md). Semua angka di bawah diambil dari `run1/summary.csv` dan `run1/sizes.csv` kecuali disebut lain.

## Lingkungan

| | |
|---|---|
| CPU | Intel Core i5-10400F @ 2,90 GHz (Comet Lake, 6 core / 12 thread, **tanpa SHA-NI**) |
| RAM | 8 GB untuk VM WSL2 (`MemTotal` 8 078 536 kB) |
| OS | Debian GNU/Linux 13 (trixie) di container Docker 28.5.1 (Docker Desktop), kernel `6.6.87.2-microsoft-standard-WSL2`, host Windows 11 |
| Compiler | GCC 14.2.0, `-O3 -DNDEBUG` (`CMAKE_BUILD_TYPE=Release`) |
| OpenSSL | 3.5.7 (9 Jun 2026), paket Debian `libssl-dev` |
| sister-sign | 0.1.0 (`main` `3bf4ae0` + perubahan T25/T26/T29 yang belum di-commit) |
| Jam | `std::chrono::steady_clock`, 1 pengukuran per operasi |
| Pengulangan | 5 pemanasan + 30 diukur; keygen 21 pasangan (+1 pemanasan); pemanasan CPU global 2 s |
| Penempatan | program `bench` di-pin ke CPU 2 (`taskset -c 2`); artefak di `/tmp` container (bukan bind mount Windows) |
| Waktu | 15 Nov 2026, run 1 dan run 2 berurutan (`bash bench/run.sh` dengan `BENCH_IN_DOCKER=1`) |

## Hasil

### Keygen (median dari 21 pasangan)

| Profil | median (ms) | P95 (ms) | min (ms) | maks (ms) |
|---|---:|---:|---:|---:|
| `ed25519` | 0,097 | 0,147 | 0,066 | 0,206 |
| `ecdsa-p256-sha256` | 0,067 | 0,105 | 0,065 | 0,106 |
| `rsa-pss-sha256` | 86,546 | 215,175 | 45,595 | 216,908 |

### Hash SHA-256 artefak (streaming 64 KiB, termasuk baca berkas)

| Ukuran | median (ms) | P95 (ms) | throughput dari median |
|---|---:|---:|---:|
| 1 KiB | 0,009 | 0,014 | 106 MiB/s |
| 1 MiB | 2,565 | 3,272 | 390 MiB/s |
| 64 MiB | 143,908 | 156,553 | 445 MiB/s |

### Sign / verify atas manifest M (≈ 300 byte, tanpa I/O)

| Profil | sign median (µs) | sign P95 (µs) | verify median (µs) | verify P95 (µs) |
|---|---:|---:|---:|---:|
| `ed25519` | 39,3 | 59,4 | 101,4 | 122,7 |
| `ecdsa-p256-sha256` | 32,9 | 50,0 | 70,0 | 81,6 |
| `rsa-pss-sha256` | 1561,4 | 1760,6 | 45,1 | 58,0 |

### End-to-end in-process (`sister-sign sign` dan `verify -json` lewat `cli::run`)

| Profil | Artefak | sign median (ms) | sign P95 (ms) | verify median (ms) | verify P95 (ms) |
|---|---|---:|---:|---:|---:|
| `ed25519` | 1 KiB | 0,360 | 0,411 | 0,403 | 0,518 |
| `ed25519` | 1 MiB | 2,564 | 2,744 | 2,595 | 2,952 |
| `ed25519` | 64 MiB | 142,464 | 154,701 | 143,175 | 159,058 |
| `ecdsa-p256-sha256` | 1 KiB | 0,360 | 0,413 | 0,359 | 0,406 |
| `ecdsa-p256-sha256` | 1 MiB | 2,552 | 2,684 | 2,551 | 2,707 |
| `ecdsa-p256-sha256` | 64 MiB | 147,074 | 158,867 | 141,877 | 153,555 |
| `rsa-pss-sha256` | 1 KiB | 2,694 | 2,899 | 0,363 | 0,458 |
| `rsa-pss-sha256` | 1 MiB | 4,798 | 5,216 | 2,653 | 2,755 |
| `rsa-pss-sha256` | 64 MiB | 145,690 | 162,426 | 146,140 | 162,850 |

### Ukuran (byte)

| Profil | privkey DER (PKCS#8) | privkey PEM | pubkey DER (SPKI) | pubkey PEM | M | signature mentah | `signature_b64` | bundle 1 KiB / 1 MiB / 64 MiB |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `ed25519` | 48 | 119 | 44 | 113 | 294 | 64 | 88 | 548 / 556 / 560 |
| `ecdsa-p256-sha256` | 138 | 241 | 91 | 178 | 304 | 64 (`r‖s`) | 88 | 564 / 572 / 572 |
| `rsa-pss-sha256` | 1792 (run 2: 1793) | 2484 | 422 | 625 | 301 | 384 | 512 | 984 / 992 / 992 |

Ukuran privkey RSA DER berbeda 1 byte antar kunci karena INTEGER DER panjangnya minimal (nol di depan dibuang). M sedikit berbeda antar profil karena panjang nama algoritma. Bundle tumbuh beberapa byte seiring jumlah digit `size` di M.

## Analisis

1. **Keygen.** RSA-3072 ≈ 1300× lebih lambat daripada Ed25519/ECDSA (median 87 ms vs ≈ 0,07–0,1 ms) karena harus mencari dua bilangan prima 1536 bit; jumlah kandidat yang diuji acak, sehingga sebarannya lebar (45–217 ms di run 1, 29–312 ms di run 2). Ed25519 dan ECDSA cukup membangkitkan skalar acak dan satu perkalian titik.
2. **Sign.** RSA-PSS (eksponen privat 3072 bit, dengan CRT) ≈ 1,56 ms, sekitar 40–50× lebih lambat daripada ECDSA (33 µs, termasuk HMAC-DRBG RFC 6979) dan Ed25519 (39 µs). Di OpenSSL 3.5, P-256 memakai implementasi assembly `nistz256` sehingga ECDSA sedikit lebih cepat daripada Ed25519.
3. **Verify.** Urutannya terbalik: RSA-PSS paling cepat (45 µs, eksponen publik e = 65537 kecil), ECDSA 70 µs (dua perkalian skalar), Ed25519 101 µs (implementasi Ed25519 OpenSSL tidak seoptimal P-256-nya; pustaka lain bisa berbeda). Ketiganya < 0,15 ms, jadi biaya verify tidak relevan untuk pipeline.
4. **Hash.** ≈ 445 MiB/s untuk 64 MiB. CPU ini tidak punya instruksi SHA-NI, jadi OpenSSL memakai jalur AVX2; di CPU dengan SHA-NI angka ini biasanya beberapa kali lebih tinggi. Untuk 1 KiB, waktu didominasi buka/tutup berkas (≈ 9 µs), bukan hash.
5. **End-to-end.** Untuk 1 KiB ada biaya tetap ≈ 0,36–0,40 ms (parse argumen, baca dan validasi PEM, parse bundle + trust store berisi 3 kunci termasuk RSA, tulis bundle). `e2e-sign` RSA 1 KiB (2,69 ms) ≈ biaya tetap (0,36) + sign primitif (1,56) + ≈ 0,77 ms; selisih terakhir ini adalah perkiraan biaya memuat privkey RSA 3072 (PEM → PKCS#8 → parameter CRT) dan verifikasi-diri setelah sign. Untuk 64 MiB, ketiga profil memakan 142–147 ms, sama dengan waktu hash (144 ms): **> 97% waktu adalah SHA-256 artefak**, jadi pilihan algoritma hanya berpengaruh untuk artefak kecil atau saat sign RSA.
6. **Ukuran.** Ed25519 paling ringkas (kunci publik 44 B, signature 64 B, bundle 548 B); ECDSA P-256 sama-sama 64 B signature dalam `r‖s` (DER akan 70–72 B); RSA-PSS 3072 signature 384 B dan bundle ≈ 1,8× lebih besar.

## Reproduksibilitas: run 1 vs run 2

`bash bench/compare.sh` membandingkan median kedua run ([`compare.md`](../bench/results/compare.md)). **28 dari 30 baris berbeda < 20%** (kebanyakan < 5%). Dua baris yang melewati batas:

| Operasi | run 1 | run 2 | Selisih | Penyebab |
|---|---:|---:|---:|---|
| `keygen ed25519` | 96,8 µs | 65,1 µs | −32,7% | Di run 1, 11 sampel pertama ≈ 93–206 µs lalu turun mendadak ke ≈ 65 µs dan stabil (`raw.csv`). Pola tangga seperti ini adalah perubahan kondisi mesin (frekuensi CPU/penjadwalan vCPU), bukan sifat Ed25519; run 2 stabil 64–72 µs sejak awal. |
| `e2e-verify ed25519 1 KiB` | 403 µs | 672 µs | +66,6% | Di run 2, 14 sampel pertama ≈ 392–495 µs (sama dengan run 1), lalu mulai sampel ke-15 melonjak ke 650–1575 µs dan tetap tinggi sampai akhir. Operasi lain di run 2 tidak terpengaruh, jadi ini gangguan sesaat dari host (VM WSL2 di desktop Windows yang juga menjalankan Docker Desktop dan editor). |

Catatan lain:

- **Keygen RSA** kali ini lolos (86,5 vs 88,0 ms, +1,7%), tetapi sebaran per run tetap lebar (lihat analisis 1). Pada percobaan sebelumnya dengan 11 dan 21 pasangan, median keygen RSA berbeda 57% dan 29% antar run. Ini memang sifat algoritmanya: median waktu pencarian prima dari 21 sampel masih punya galat besar, jadi angka keygen RSA sebaiknya dibaca sebagai orde besaran (puluhan sampai ratusan ms), bukan nilai pasti.
- **Percobaan sebelumnya** (data ditimpa, dicatat dari log): percobaan 1 berjalan bersamaan dengan pemindaian berkas MiKTeX di host, sehingga `e2e-verify rsa 1 MiB` berbeda 25%. Percobaan 2 tanpa beban lain, tetapi operasi pertama run 1 terukur tepat ≈ 2× lebih lambat (Ed25519 sign 74,5 vs 39,3 µs, verify 202,6 vs 103,2 µs). Karena itu ditambahkan pemanasan CPU global 2 s dan pin ke satu CPU; efek 2× itu hilang di run final.
- Operasi dengan median ≥ 1 ms (hash 1 MiB/64 MiB, sign RSA, semua e2e ≥ 1 MiB) berbeda ≤ 14%; e2e 64 MiB ≤ 3,1%.

## Batasan

- Satu mesin, di dalam VM WSL2 dengan host desktop yang tidak diisolasi; angka sub-milidetik rentan gangguan (lihat di atas). Angka relatif antar profil konsisten di semua percobaan.
- `e2e-*` diukur in-process. Start proses, dynamic linking, dan `docker run` (biasanya beberapa ratus ms untuk container) tidak termasuk.
- Page cache hangat (berkas yang sama dibaca berulang), jadi hash mengukur CPU, bukan disk.
- OpenSSL dari paket Debian; build lain (mis. dengan SHA-NI atau pustaka lain seperti libsodium untuk Ed25519) akan memberi angka berbeda.
