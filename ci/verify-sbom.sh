#!/usr/bin/env bash
# Tahap Verify untuk SBOM: `sbom verify -json` (tanda tangan SBOM, Algoritma 2 + isi SBOM)
# lalu `sbom check -json` (SHA-256 artefak rilis == SHA-256 di SBOM). Tanpa privkey; trust store
# dari sumber tepercaya. Keduanya selalu dijalankan supaya buktinya lengkap.
#
#   bash ci/verify-sbom.sh <image@digest> <sbom> <bundle-sbom> <trust-store> <package> <versi> \
#       <artefak> <dir-hasil> <label>
#
# Hasil: <dir-hasil>/sbom-verify-<label>.json dan sbom-check-<label>.json (+ .exit, .stderr).
# Exit != 0 bila salah satu gagal (exit code asli sister-sign).
set -euo pipefail
# shellcheck source=ci/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

[ "$#" -eq 9 ] || die "usage: ci/verify-sbom.sh <image@digest> <sbom> <bundle> <trust-store> <package> <version> <artifact> <out-dir> <label>"
ref="$1" sbom="$2" bundle="$3" store="$4" package="$5" version="$6" artifact="$7" out="$8" label="$9"
require_digest_ref "$ref"
for f in "$sbom" "$bundle" "$store" "$artifact"; do [ -f "$f" ] || die "berkas tidak ada: $f"; done

sdir="$(host_path "$(dirname "$sbom")")"
bdir="$(host_path "$(dirname "$bundle")")"
tdir="$(host_path "$(dirname "$store")")"
adir="$(host_path "$(dirname "$artifact")")"
s="/sbom/$(basename "$sbom")"

rc_verify=0
json_step "$out/sbom-verify-$label.json" "$ref" -v "$sdir:/sbom:ro" -v "$bdir:/bundle:ro" \
  -v "$tdir:/trust:ro" -- sbom verify -sbom "$s" -bundle "/bundle/$(basename "$bundle")" \
  -trust-store "/trust/$(basename "$store")" -package "$package" -version "$version" -json ||
  rc_verify=$?
rc_check=0
json_step "$out/sbom-check-$label.json" "$ref" -v "$sdir:/sbom:ro" -v "$adir:/in:ro" -- \
  sbom check -sbom "$s" -file "/in/$(basename "$artifact")" -json || rc_check=$?

if [ "$rc_verify" -ne 0 ] || [ "$rc_check" -ne 0 ]; then
  echo "::error::SBOM DITOLAK: sbom verify exit=$rc_verify, sbom check exit=$rc_check. Deploy tidak boleh jalan."
  [ "$rc_verify" -ne 0 ] && exit "$rc_verify"
  exit "$rc_check"
fi
echo "SBOM OK: $(basename "$sbom") sah dan terikat ke $(basename "$artifact")"
