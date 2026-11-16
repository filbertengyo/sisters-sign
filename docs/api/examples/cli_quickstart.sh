#!/usr/bin/env bash
# Contoh CLI (T38) yang ditampilkan di dokumentasi API. Dijalankan ctest (api_example_cli), jadi
# setiap perintah di dokumentasi benar-benar jalan dengan exit code yang tertulis.
#
#   bash docs/api/examples/cli_quickstart.sh <path/ke/sister-sign> <direktori-kerja-kosong>
set -euo pipefail
SIS="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
work="$2"
mkdir -p "$work"
cd "$work"
# Di dokumentasi perintah ditulis sebagai `sister-sign ...`.
sister-sign() { "$SIS" "$@" </dev/null; }
# expect_exit N perintah... : jalankan dan pastikan exit code persis N.
expect_exit() {
  local want="$1" rc=0
  shift
  "$@" || rc=$?
  [ "$rc" -eq "$want" ] || {
    echo "FAIL: '$*' exit $rc, seharusnya $want" >&2
    exit 1
  }
}

printf 'isi artefak rilis' >app.bin

# [keygen]
# Buat pasangan kunci: app-key.key.pem (privkey PKCS#8, mode 0600) + app-key.pub.pem (SPKI).
sister-sign keygen -algorithm ed25519 -out app-key
# [keygen]

# [trust]
# Percayai pubkey untuk package "demo" (store dibuat bila belum ada), lalu lihat isinya.
sister-sign trust add -store trust.json -key app-key.pub.pem -package demo
sister-sign trust list -store trust.json
# [trust]

# [sign]
# Tandatangani artefak -> bundle (manifest kanonik + signature).
sister-sign sign -file app.bin -package demo -version 1.0.0 -key app-key.key.pem \
  -out app.bundle.json
# [sign]

# [verify]
# Verifikasi: exit 0 dan satu baris JSON ke stdout.
sister-sign verify -file app.bin -bundle app.bundle.json -trust-store trust.json \
  -package demo -version 1.0.0 -json
# [verify]

# [verify-fail]
# Versi yang diharapkan berbeda dari manifest -> METADATA_MISMATCH, exit 1.
sister-sign verify -file app.bin -bundle app.bundle.json -trust-store trust.json \
  -package demo -version 2.0.0 -json || echo "exit $?"
# Artefak yang tidak ada -> INPUT_ERROR, exit 2.
sister-sign verify -file hilang.bin -bundle app.bundle.json -trust-store trust.json \
  -package demo -version 1.0.0 -json || echo "exit $?"
# [verify-fail]

# Pemeriksaan exit code untuk ctest (tidak ditampilkan di dokumentasi).
expect_exit 0 sister-sign verify -file app.bin -bundle app.bundle.json -trust-store trust.json \
  -package demo -version 1.0.0
expect_exit 1 sister-sign verify -file app.bin -bundle app.bundle.json -trust-store trust.json \
  -package demo -version 2.0.0
expect_exit 2 sister-sign verify -file hilang.bin -bundle app.bundle.json -trust-store trust.json \
  -package demo -version 1.0.0
printf 'isi artefak palsu' >app.bin
expect_exit 1 sister-sign verify -file app.bin -bundle app.bundle.json -trust-store trust.json \
  -package demo -version 1.0.0
echo "cli_quickstart: semua contoh lulus"
