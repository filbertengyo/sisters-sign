#!/usr/bin/env bash
# Uji tests/integration/run.sh tanpa secret dan tanpa rilis: image lokal di-push ke registry lokal
# (supaya bisa dirujuk BY DIGEST), kunci + trust store SEMENTARA dibuat dengan image itu, lalu
# C01-C05 dijalankan. Dipakai di job PR build-image dan untuk mencoba lokal.
#
# Ini BUKAN bukti C01 untuk laporan (image dibangun dari source di runner yang sama); bukti resmi
# = workflow integration.yml terhadap image rilis di GHCR dengan kunci demo dari secret.
#
#   bash tests/integration/selftest.sh <image-lokal> <registry> [<dir-output>]
#   # mis. bash tests/integration/selftest.sh sister-sign:dev localhost:5000 out/integration
#
# Registry lokal: docker run -d -p 5000:5000 --name registry registry:2
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci/lib.sh
. "$here/../../ci/lib.sh"

img="${1:?usage: tests/integration/selftest.sh <local-image> <registry-host:port> [out-dir]}"
registry="${2:?usage: tests/integration/selftest.sh <local-image> <registry-host:port> [out-dir]}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
out="${3:-$tmp/out}"
export TMPDIR="$tmp/tmp" # temp file kunci dari sign-artifact.sh dibuat di sini -> bisa diaudit
mkdir -p "$TMPDIR" "$tmp/keys"

docker tag "$img" "$registry/sister-sign:integration"
docker push --quiet "$registry/sister-sign:integration" >/dev/null
ref="$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$registry/sister-sign:integration" |
  grep -F "$registry/sister-sign@sha256:" | head -n1)"
require_digest_ref "$ref"
echo "image: $ref"

kdir="$(host_path "$tmp/keys")"
for spec in ed25519:ED25519 ecdsa-p256-sha256:ECDSA_P256 rsa-pss-sha256:RSA_PSS; do
  alg="${spec%%:*}"
  tool_run "$ref" -v "$kdir:/k" -- keygen -algorithm "$alg" -out "/k/$alg" >/dev/null
  tool_run "$ref" -v "$kdir:/k" -- trust add -store /k/trust.json -key "/k/$alg.pub.pem" \
    -package sister-sign >/dev/null
  export "DEMO_KEY_${spec#*:}=$(cat "$tmp/keys/$alg.key.pem")"
done
export TRUST_STORE="$tmp/keys/trust.json"

bash "$here/run.sh" "$ref" "$out"
[ "$(grep -c '| PASS |' "$out/results.md")" -eq 8 ] || die "results.md tidak memuat 8 baris PASS"
[ -z "$(ls -A "$TMPDIR")" ] || die "temp file kunci tertinggal di $TMPDIR"
echo "selftest: C01-C05 sesuai harapan (output: $out)"
