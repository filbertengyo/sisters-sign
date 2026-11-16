#!/usr/bin/env bash
# Tahap Sign. Privkey HANYA dari variabel lingkungan SIGNING_KEY (CI secret), ditulis ke
# temp file 0600 di luar workspace, di-mount :ro ke container, lalu dihapus. Isi kunci tidak
# pernah dicetak, tidak masuk image, dan tidak masuk direktori output.
#
#   SIGNING_KEY="$(cat k.key.pem)" bash ci/sign-artifact.sh <image@digest> <artefak> <package> \
#       <versi> <bundle-output> [<sbom> <bundle-sbom-output>]
#
# Dengan <sbom>, SBOM ikut ditandatangani (`sbom sign`) memakai temp file kunci yang sama
# dalam satu sesi, lalu kunci dihapus sekali.
set -euo pipefail
# shellcheck source=ci/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

[ "$#" -eq 5 ] || [ "$#" -eq 7 ] ||
  die "usage: SIGNING_KEY=... ci/sign-artifact.sh <image@digest> <artifact> <package> <version> <out-bundle> [<sbom> <out-sbom-bundle>]"
ref="$1" artifact="$2" package="$3" version="$4" out="$5" sbom="${6:-}" sbom_out="${7:-}"
require_digest_ref "$ref"
[ -f "$artifact" ] || die "artefak tidak ada: $artifact"
[ -z "$sbom" ] || [ -f "$sbom" ] || die "SBOM tidak ada: $sbom"
[ -n "${SIGNING_KEY:-}" ] || die "SIGNING_KEY kosong: secret privkey belum diset untuk job ini"

keydir="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/sister-sign-key.XXXXXX")"
cleanup() {
  if [ -n "${keydir:-}" ] && [ -d "$keydir" ]; then
    # Timpa dulu sebelum dihapus (best effort; di runner ephemeral disk ikut dibuang).
    if [ -f "$keydir/signing.key.pem" ]; then
      dd if=/dev/zero of="$keydir/signing.key.pem" bs=1 count="$(wc -c <"$keydir/signing.key.pem")" \
        conv=notrunc status=none
    fi
    rm -rf "$keydir"
  fi
}
trap cleanup EXIT
chmod 0700 "$keydir"
(
  umask 077
  key="${SIGNING_KEY//$'\r'/}"
  while [[ "$key" == *[[:space:]] ]]; do key="${key%?}"; done
  printf '%s\n' "$key" >"$keydir/signing.key.pem"
)
unset SIGNING_KEY

mkdir -p "$(dirname "$out")"
indir="$(host_path "$(dirname "$artifact")")"
outdir="$(host_path "$(dirname "$out")")"
kdir="$(host_path "$keydir")"
name="$(basename "$artifact")"
bundle="$(basename "$out")"

tool_run "$ref" -v "$indir:/in:ro" -v "$kdir:/key:ro" -v "$outdir:/out" -- \
  sign -file "/in/$name" -package "$package" -version "$version" -key /key/signing.key.pem \
  -out "/out/$bundle"
if [ -n "$sbom" ]; then
  mkdir -p "$(dirname "$sbom_out")"
  tool_run "$ref" -v "$(host_path "$(dirname "$sbom")"):/sbom:ro" -v "$kdir:/key:ro" \
    -v "$(host_path "$(dirname "$sbom_out")"):/sbom-out" -- \
    sbom sign -sbom "/sbom/$(basename "$sbom")" -package "$package" -version "$version" \
    -key /key/signing.key.pem -out "/sbom-out/$(basename "$sbom_out")"
fi

cleanup
keydir=""

# Bukti: output tidak memuat privkey dan temp file kunci sudah hilang.
[ -s "$out" ] || die "bundle tidak terbentuk: $out"
[ -z "$sbom" ] || [ -s "$sbom_out" ] || die "bundle SBOM tidak terbentuk: $sbom_out"
for d in "$(dirname "$out")" ${sbom_out:+"$(dirname "$sbom_out")"}; do
  if grep -rqE -- "$PRIVKEY_PATTERN" "$d"; then die "direktori output memuat privkey: $d"; fi
done
echo "bundle: $out ($(wc -c <"$out" | tr -d ' ') byte); privkey sementara sudah dihapus" >&2
