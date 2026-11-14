#!/usr/bin/env bash
# Membuktikan harness benar: kasus lulus terdeteksi PASS, kasus yang sengaja salah terdeteksi
# FAIL/ERROR, dan exit code runner non-nol bila ada yang gagal.
#   selftest.sh <biner sister-sign> <direktori hasil sementara>
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$1"
OUT="$2"
rc=0
check() { # check <deskripsi> <kondisi: 0=benar>
  if [ "$2" -eq 0 ]; then echo "ok   - $1"; else echo "FAIL - $1"; rc=1; fi
}

bash "$HERE/run.sh" "$BIN" "$HERE/selftest" "$OUT/selftest" >"$OUT/selftest.log" 2>&1
runner_rc=$?
check "runner exit non-nol bila ada kasus gagal" "$([ "$runner_rc" -ne 0 ] && echo 0 || echo 1)"

tsv="$OUT/selftest/results.tsv"
verdict_of() { awk -F '\t' -v id="$1" '$1 == id { print $6 }' "$tsv"; }
check "P01 terdeteksi PASS" "$([ "$(verdict_of P01-should-pass)" = PASS ] && echo 0 || echo 1)"
check "F01 (exit salah) terdeteksi FAIL" "$([ "$(verdict_of F01-wrong-exit)" = FAIL ] && echo 0 || echo 1)"
check "F02 (status salah) terdeteksi FAIL" "$([ "$(verdict_of F02-wrong-status)" = FAIL ] && echo 0 || echo 1)"
check "F03 (persiapan gagal) terdeteksi ERROR" "$([ "$(verdict_of F03-setup-fails)" = ERROR ] && echo 0 || echo 1)"
check "tabel markdown dibuat" "$(grep -q '^| ID |' "$OUT/selftest/results.md" && echo 0 || echo 1)"
check "bukti per kasus tersimpan" "$([ -f "$OUT/selftest/P01-should-pass/commands.txt" ] && [ -f "$OUT/selftest/P01-should-pass/expected.txt" ] && [ -f "$OUT/selftest/P01-should-pass/actual.txt" ] && [ -f "$OUT/selftest/P01-should-pass/stdout.txt" ] && echo 0 || echo 1)"
check "privkey tidak disalin ke bukti" "$([ -z "$(find "$OUT/selftest" -name '*.key.pem')" ] && echo 0 || echo 1)"
exit $rc
