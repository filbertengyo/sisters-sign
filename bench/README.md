# Benchmark (T29)

Program: [`bench_main.cpp`](bench_main.cpp) (target CMake `bench`), statistik: [`stats.hpp`](stats.hpp) (diuji di `tests/unit/bench_stats_test.cpp`). Hasil dan analisis: [`docs/benchmark.md`](../docs/benchmark.md). Data mentah: [`results/`](results/).

## Cara menjalankan

```sh
# Linux dengan GCC >= 14, CMake >= 3.31, OpenSSL >= 3.5 (mis. debian:trixie): build Release, 2 run, bandingkan
bash bench/run.sh                      # -> bench/results/{run1,run2,compare.md}

# di mesin lain (Windows/macOS/Ubuntu lama): build + jalan di container debian:trixie
BENCH_IN_DOCKER=1 bash bench/run.sh

# satu run manual dengan parameter sendiri
cmake -B build-release -DCMAKE_BUILD_TYPE=Release && cmake --build build-release --target bench
./build-release/bench -out bench/out -iterations 30 -warmup 5 -keygen 21 -sizes 1024,1048576,67108864
bash bench/compare.sh bench/results/run1/summary.csv bench/results/run2/summary.csv
```

`bench` menolak `-iterations < 30`, `-warmup < 5`, dan `-keygen < 5` (batas minimum T29). Jangan jalankan pekerjaan berat lain selama benchmark.

## Metode

| Aspek | Keputusan |
|---|---|
| Jam | `std::chrono::steady_clock` (monotonik), satu pengukuran per operasi, resolusi ns |
| Pengulangan | 5 pemanasan (tidak dihitung, tetap dicatat di `raw.csv` sebagai `warmup`) + 30 diukur per kombinasi |
| Keygen | 21 pasangan per profil (+1 pemanasan), dilaporkan median; pasangan pertama dipakai untuk pengukuran lain |
| Artefak | 3 ukuran: 1 KiB, 1 MiB, 64 MiB. Isi pseudo-acak deterministik (xorshift64\*). **Berkas yang sama** dipakai ketiga profil |
| `hash` | SHA-256 streaming berkas, 64 KiB per baca (jalur yang sama dengan CLI `sign`/`verify`), termasuk baca dari disk (page cache hangat setelah pemanasan) |
| `sign` / `verify` | `crypto::sign` / `crypto::verify` atas byte manifest kanonik M (≈ 300 byte), tanpa I/O |
| `e2e-sign` | `sister-sign sign` dipanggil **in-process** lewat `cli::run`: parse argumen, baca privkey PEM, hash artefak, susun M, sign, verifikasi-diri, tulis bundle |
| `e2e-verify` | `sister-sign verify -json` in-process: baca bundle + trust store (3 kunci), parse strict, lookup, verify signature, cek metadata, hash artefak |
| Tidak diukur | start proses / dynamic linking / `docker run` (beberapa ms; di luar kendali kode ini) |
| Ukuran | privkey DER PKCS#8, pubkey DER SPKI, berkas PEM, M, signature mentah (pra-base64) dan base64-nya, bundle per ukuran artefak |
| Statistik | median (n genap: rata-rata dua tengah), **P95 nearest-rank**: rank = ⌈0,95·n⌉ dengan posisi mulai 1 (n = 30 → sampel terurut ke-29), min, maks, rata-rata |
| Reproduksibilitas | dijalankan 2x; `compare.sh` menandai median yang berbeda ≥ 20% (penyebab dicatat di `docs/benchmark.md`) |
| Lingkungan | dicatat otomatis di `env.txt`: CPU, jumlah CPU logis, RAM, OS, kernel, container atau tidak, compiler, build teroptimasi atau tidak, versi OpenSSL |

## Berkas keluaran

| Berkas | Kolom / isi |
|---|---|
| `raw.csv` | `op,algorithm,size_bytes,phase,iteration,ns`: setiap sampel (pemanasan + diukur) |
| `summary.csv` | `op,algorithm,size_bytes,n,median_us,p95_us,min_us,max_us,mean_us` (hanya sampel `measure`) |
| `sizes.csv` | `algorithm,item,bytes` |
| `env.txt` | `kunci=nilai` lingkungan |
| `summary.md` | tabel ringkasan yang sama dengan `summary.csv`, siap ditempel |
| `../compare.md` | selisih median run 1 vs run 2 |

`algorithm` = `-` untuk operasi yang tidak bergantung profil (`hash`); `size_bytes` = 0 untuk operasi yang tidak bergantung ukuran artefak (`keygen`, `sign`, `verify`).

Kunci yang dipakai dibuat saat itu juga di direktori kerja sementara dan dihapus di akhir; tidak ada kunci di `results/`.
