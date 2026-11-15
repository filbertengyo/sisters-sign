Lingkungan: `timestamp_utc=2026-11-15T07:37:51Z` `cpu_model=Intel(R) Core(TM) i5-10400F CPU @ 2.90GHz` `logical_cpus=12` `mem_total=8078536 kB` `os=Debian GNU/Linux 13 (trixie)` `kernel=Linux 6.6.87.2-microsoft-standard-WSL2 x86_64` `container=docker` `compiler=gcc 14.2.0` `optimized=yes` `openssl=OpenSSL 3.5.7 9 Jun 2026` `sister_sign=0.1.0` `clock=std::chrono::steady_clock` `iterations=30` `warmup=5` `keygen_pairs=21` `cpu_warmup=2 s SHA-256 sebelum pengukuran pertama` 

### Keygen (21 pasangan per profil)

| Profil | median (ms) | P95 (ms) | min (ms) | max (ms) |
|---|---:|---:|---:|---:|
| `ed25519` | 0.065 | 0.072 | 0.065 | 0.102 |
| `ecdsa-p256-sha256` | 0.065 | 0.085 | 0.064 | 0.090 |
| `rsa-pss-sha256` | 88.018 | 208.295 | 29.370 | 311.905 |

### Hash SHA-256 artefak (streaming 64 KiB)

| Ukuran | median (ms) | P95 (ms) | throughput dari median (MiB/s) |
|---|---:|---:|---:|
| 1 KiB | 0.009 | 0.010 | 104 |
| 1 MiB | 2.205 | 2.353 | 454 |
| 64 MiB | 147.087 | 173.636 | 435 |

### Sign / verify atas manifest M

| Profil | sign median (µs) | sign P95 (µs) | verify median (µs) | verify P95 (µs) |
|---|---:|---:|---:|---:|
| `ed25519` | 39.5 | 57.7 | 119.6 | 152.9 |
| `ecdsa-p256-sha256` | 33.1 | 47.9 | 70.8 | 86.2 |
| `rsa-pss-sha256` | 1625.0 | 1693.4 | 45.5 | 53.6 |

### End-to-end in-process (`sign` dan `verify -json`)

| Profil | Artefak | sign median (ms) | sign P95 (ms) | verify median (ms) | verify P95 (ms) |
|---|---|---:|---:|---:|---:|
| `ed25519` | 1 KiB | 0.372 | 0.697 | 0.672 | 1.212 |
| `ed25519` | 1 MiB | 2.554 | 2.839 | 2.598 | 2.742 |
| `ed25519` | 64 MiB | 142.936 | 163.238 | 141.956 | 149.036 |
| `ecdsa-p256-sha256` | 1 KiB | 0.375 | 0.505 | 0.372 | 0.474 |
| `ecdsa-p256-sha256` | 1 MiB | 2.566 | 2.911 | 2.553 | 2.718 |
| `ecdsa-p256-sha256` | 64 MiB | 142.580 | 146.448 | 141.862 | 148.445 |
| `rsa-pss-sha256` | 1 KiB | 2.704 | 4.016 | 0.360 | 0.458 |
| `rsa-pss-sha256` | 1 MiB | 5.046 | 5.160 | 2.744 | 2.974 |
| `rsa-pss-sha256` | 64 MiB | 144.499 | 153.741 | 141.564 | 152.961 |

Ukuran (byte): lihat `sizes.csv`.
