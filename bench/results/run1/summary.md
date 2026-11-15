Lingkungan: `timestamp_utc=2026-11-15T07:37:10Z` `cpu_model=Intel(R) Core(TM) i5-10400F CPU @ 2.90GHz` `logical_cpus=12` `mem_total=8078536 kB` `os=Debian GNU/Linux 13 (trixie)` `kernel=Linux 6.6.87.2-microsoft-standard-WSL2 x86_64` `container=docker` `compiler=gcc 14.2.0` `optimized=yes` `openssl=OpenSSL 3.5.7 9 Jun 2026` `sister_sign=0.1.0` `clock=std::chrono::steady_clock` `iterations=30` `warmup=5` `keygen_pairs=21` `cpu_warmup=2 s SHA-256 sebelum pengukuran pertama` 

### Keygen (21 pasangan per profil)

| Profil | median (ms) | P95 (ms) | min (ms) | max (ms) |
|---|---:|---:|---:|---:|
| `ed25519` | 0.097 | 0.147 | 0.066 | 0.206 |
| `ecdsa-p256-sha256` | 0.067 | 0.105 | 0.065 | 0.106 |
| `rsa-pss-sha256` | 86.546 | 215.175 | 45.595 | 216.908 |

### Hash SHA-256 artefak (streaming 64 KiB)

| Ukuran | median (ms) | P95 (ms) | throughput dari median (MiB/s) |
|---|---:|---:|---:|
| 1 KiB | 0.009 | 0.014 | 106 |
| 1 MiB | 2.565 | 3.272 | 390 |
| 64 MiB | 143.908 | 156.553 | 445 |

### Sign / verify atas manifest M

| Profil | sign median (µs) | sign P95 (µs) | verify median (µs) | verify P95 (µs) |
|---|---:|---:|---:|---:|
| `ed25519` | 39.3 | 59.4 | 101.4 | 122.7 |
| `ecdsa-p256-sha256` | 32.9 | 50.0 | 70.0 | 81.6 |
| `rsa-pss-sha256` | 1561.4 | 1760.6 | 45.1 | 58.0 |

### End-to-end in-process (`sign` dan `verify -json`)

| Profil | Artefak | sign median (ms) | sign P95 (ms) | verify median (ms) | verify P95 (ms) |
|---|---|---:|---:|---:|---:|
| `ed25519` | 1 KiB | 0.360 | 0.411 | 0.403 | 0.518 |
| `ed25519` | 1 MiB | 2.564 | 2.744 | 2.595 | 2.952 |
| `ed25519` | 64 MiB | 142.464 | 154.701 | 143.175 | 159.058 |
| `ecdsa-p256-sha256` | 1 KiB | 0.360 | 0.413 | 0.359 | 0.406 |
| `ecdsa-p256-sha256` | 1 MiB | 2.552 | 2.684 | 2.551 | 2.707 |
| `ecdsa-p256-sha256` | 64 MiB | 147.074 | 158.867 | 141.877 | 153.555 |
| `rsa-pss-sha256` | 1 KiB | 2.694 | 2.899 | 0.363 | 0.458 |
| `rsa-pss-sha256` | 1 MiB | 4.798 | 5.216 | 2.653 | 2.755 |
| `rsa-pss-sha256` | 64 MiB | 145.690 | 162.426 | 146.140 | 162.850 |

Ukuran (byte): lihat `sizes.csv`.
