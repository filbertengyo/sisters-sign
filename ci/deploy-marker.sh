#!/usr/bin/env bash
# Tahap Deploy: "deploy" = salin artefak yang SUDAH diverifikasi + bundle ke direktori
# deploy dan tulis berkas penanda DEPLOYED. Dipanggil hanya setelah semua verify lulus
# (`needs: verify` di workflow; urutan yang sama di ci/pipeline-local.sh).
#
#   bash ci/deploy-marker.sh <artefak> <sha256-yang-diverifikasi> <dir-bundle> <dir-hasil-verify> \
#       <image@digest> <dir-deploy> [<sbom>]
#
# Semua hasil di <dir-hasil-verify> (verify artefak, dan sbom verify/check bila ada) harus OK.
set -euo pipefail
# shellcheck source=ci/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

[ "$#" -eq 6 ] || [ "$#" -eq 7 ] ||
  die "usage: ci/deploy-marker.sh <artifact> <sha256> <bundle-dir> <verify-dir> <image@digest> <deploy-dir> [<sbom>]"
artifact="$1" want_sha="$2" bundles="$3" results="$4" ref="$5" deploy="$6" sbom="${7:-}"

# Artefak yang dideploy harus byte-identik dengan yang diverifikasi.
got_sha="$(sha256sum "$artifact" | cut -d' ' -f1)"
[ "$got_sha" = "$want_sha" ] || die "sha256 artefak berubah setelah verify ($got_sha != $want_sha)"

# Setiap hasil verify harus exit 0 + valid/OK.
n=0
for exitf in "$results"/*.json.exit; do
  [ -e "$exitf" ] || die "tidak ada hasil verify di $results"
  json="${exitf%.exit}"
  [ "$(cat "$exitf")" = "0" ] || die "hasil verify $(basename "$json") tidak exit 0"
  grep -q '^{"valid":true,"status":"OK",' "$json" || die "hasil verify $(basename "$json") bukan OK"
  n=$((n + 1))
done

mkdir -p "$deploy"
cp "$artifact" "$deploy/"
cp "$bundles"/*.bundle.json "$deploy/"
cp "$results"/*.json "$deploy/"
if [ -n "$sbom" ]; then
  [ -n "$(find "$results" -name 'sbom-check-*.json.exit')" ] || die "SBOM tanpa hasil sbom check"
  cp "$sbom" "$deploy/"
fi
{
  echo "status=DEPLOYED"
  echo "artifact=$(basename "$artifact")"
  echo "sha256=$got_sha"
  echo "image=$ref"
  echo "verified_results=$n"
  if [ -n "$sbom" ]; then
    echo "sbom=$(basename "$sbom")"
    echo "sbom_sha256=$(sha256sum "$sbom" | cut -d' ' -f1)"
  fi
  echo "commit=${GITHUB_SHA:-local}"
  echo "run=${GITHUB_RUN_ID:-local}"
  echo "time=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >"$deploy/DEPLOYED"
(cd "$deploy" && sha256sum -- * >SHA256SUMS.tmp && mv SHA256SUMS.tmp SHA256SUMS)
cat "$deploy/DEPLOYED"
