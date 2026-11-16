#!/usr/bin/env bash
# Tahap Verify (T26): `sister-sign verify -json` di container, TANPA privkey. Trust store harus
# berasal dari sumber tepercaya (berkas di repo/runner), bukan dari bundle atau artefak yang sedang
# diverifikasi.
#
#   bash ci/verify-artifact.sh <image@digest> <artefak> <bundle> <trust-store> <package> <versi> \
#       <hasil.json>
#
# Exit code = exit code ASLI sister-sign (0 OK, 1 ditolak, 2 input salah). Selain itu 1 bila
# exit 0 tetapi JSON tidak menyatakan valid=true,status=OK. Hasil JSON selalu ditulis (bukti),
# exit code ditulis ke <hasil.json>.exit.
set -euo pipefail
# shellcheck source=ci/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

[ "$#" -eq 7 ] || die "usage: ci/verify-artifact.sh <image@digest> <artifact> <bundle> <trust-store> <package> <version> <out-json>"
ref="$1" artifact="$2" bundle="$3" store="$4" package="$5" version="$6" result="$7"
require_digest_ref "$ref"
for f in "$bundle" "$store"; do [ -f "$f" ] || die "berkas tidak ada: $f"; done
# Artefak yang hilang TIDAK dicek di sini: CLI yang harus menolaknya (INPUT_ERROR, exit 2), supaya
# exit code yang tercatat adalah exit code asli program (uji C04). Direktorinya harus ada, karena
# docker membuat direktori bind mount yang belum ada.
[ -d "$(dirname "$artifact")" ] || die "direktori artefak tidak ada: $(dirname "$artifact")"

mkdir -p "$(dirname "$result")"
adir="$(host_path "$(dirname "$artifact")")"
bdir="$(host_path "$(dirname "$bundle")")"
tdir="$(host_path "$(dirname "$store")")"

set +e
tool_run "$ref" -v "$adir:/in:ro" -v "$bdir:/bundle:ro" -v "$tdir:/trust:ro" -- \
  verify -file "/in/$(basename "$artifact")" -bundle "/bundle/$(basename "$bundle")" \
  -trust-store "/trust/$(basename "$store")" -package "$package" -version "$version" -json \
  >"$result" 2>"$result.stderr"
rc=$?
set -e
printf '%s\n' "$rc" >"$result.exit"

echo "exit=$rc"
echo "stdout: $(cat "$result")"
if [ -s "$result.stderr" ]; then echo "stderr: $(cat "$result.stderr")"; fi

if [ "$rc" -ne 0 ]; then
  status="$(sed -n 's/.*"status":"\([A-Z_]*\)".*/\1/p' "$result")"
  echo "::error::verify DITOLAK: status=${status:-?} exit=$rc. Deploy tidak boleh jalan."
  exit "$rc"
fi
[ "$(wc -l <"$result" | tr -d ' ')" = "1" ] || die "stdout verify -json bukan satu baris JSON"
if command -v jq >/dev/null 2>&1; then
  jq -e '.valid == true and .status == "OK"' "$result" >/dev/null ||
    die "exit 0 tetapi JSON tidak menyatakan valid/OK"
else
  grep -q '^{"valid":true,"status":"OK",' "$result" || die "exit 0 tetapi JSON tidak menyatakan valid/OK"
fi
echo "verify OK: $(basename "$artifact") ($package $version)"
