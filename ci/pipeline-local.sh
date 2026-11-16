#!/usr/bin/env bash
# Jalankan pipeline contoh di luar GitHub Actions dengan urutan dan skrip yang SAMA dengan
# .github/workflows/release-pipeline.yml: Persiapan -> Sign (x3 algoritma) -> Verify -> Deploy.
#
#   bash ci/pipeline-local.sh <image@digest> <dir-privkey> <dir-kerja> [--tamper]
#
# <dir-privkey> berisi demo-ed25519.key.pem, demo-ecdsa-p256.key.pem, demo-rsa-pss.key.pem (kunci
# demo, TIDAK ada di repo). <dir-kerja> harus kosong/belum ada. --tamper mengubah 1 byte artefak
# setelah sign: verify harus gagal dan deploy tidak boleh jalan.
# Exit 0 hanya bila berkas penanda <dir-kerja>/deploy/DEPLOYED terbentuk.
#
# TRUST_STORE (opsional) mengganti ci/trust-store.json, mis. untuk kunci sementara di
# ci/test-pipeline.sh.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci/lib.sh
. "$here/lib.sh"

[ "$#" -ge 3 ] || die "usage: ci/pipeline-local.sh <image@digest> <key-dir> <work-dir> [--tamper]"
ref="$1" keys="$2" work="$3" tamper="${4:-}"
if [ -e "$work" ] && [ -n "$(ls -A "$work")" ]; then die "direktori kerja tidak kosong: $work"; fi
mkdir -p "$work"
package="sister-sign"
store="${TRUST_STORE:-$here/trust-store.json}"

echo "== [1/4] Persiapan: pull image by digest + artefak rilis"
version="$(bash "$here/resolve-image.sh" "$ref" | sed -n 's/^version=//p')"
meta="$(bash "$here/extract-binary.sh" "$ref" "$work/dist")"
name="$(sed -n 's/^name=//p' <<<"$meta")"
sha256="$(sed -n 's/^sha256=//p' <<<"$meta")"
artifact="$work/dist/$name"
sbom="$work/dist/$name.cdx.json" # SBOM yang mengikat SHA-256 artefak, ikut ditandatangani
bash "$here/make-sbom.sh" "$ref" "$artifact" >"$sbom"

echo "== [2/4] Sign (artefak + SBOM)"
for spec in ed25519:demo-ed25519 ecdsa-p256-sha256:demo-ecdsa-p256 rsa-pss-sha256:demo-rsa-pss; do
  alg="${spec%%:*}"
  SIGNING_KEY="$(cat "$keys/${spec#*:}.key.pem")" \
    bash "$here/sign-artifact.sh" "$ref" "$artifact" "$package" "$version" \
    "$work/bundles/$name.$alg.bundle.json" "$sbom" "$work/bundles/$name.cdx.json.$alg.bundle.json"
done

if [ "$tamper" = "--tamper" ]; then
  echo "== (uji negatif) ubah 1 byte artefak setelah sign"
  printf '\x00' | dd of="$artifact" bs=1 seek=1 conv=notrunc status=none
fi

echo "== [3/4] Verify (tanpa privkey, trust store dari repo)"
failed=0
for alg in ed25519 ecdsa-p256-sha256 rsa-pss-sha256; do
  if ! bash "$here/verify-artifact.sh" "$ref" "$artifact" "$work/bundles/$name.$alg.bundle.json" \
    "$store" "$package" "$version" "$work/verify/verify-$alg.json"; then
    failed=1
  fi
  if ! bash "$here/verify-sbom.sh" "$ref" "$sbom" "$work/bundles/$name.cdx.json.$alg.bundle.json" \
    "$store" "$package" "$version" "$artifact" "$work/verify" "$alg"; then
    failed=1
  fi
done
if [ "$failed" -ne 0 ]; then
  echo "== [4/4] Deploy DILEWATI: ada verify yang gagal"
  [ ! -e "$work/deploy/DEPLOYED" ] || die "berkas penanda ada padahal verify gagal"
  exit 1
fi

echo "== [4/4] Deploy"
bash "$here/deploy-marker.sh" "$artifact" "$sha256" "$work/bundles" "$work/verify" "$ref" "$work/deploy" \
  "$sbom"
[ -f "$work/deploy/DEPLOYED" ] || die "berkas penanda tidak terbentuk"
if grep -rqE -- "$PRIVKEY_PATTERN" "$work"; then die "direktori kerja memuat privkey"; fi
echo "OK: $work/deploy/DEPLOYED"
