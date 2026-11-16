#!/usr/bin/env bash
# Uji pipeline contoh tanpa secret: push image ke registry lokal supaya bisa dirujuk BY
# DIGEST, buat kunci + trust store SEMENTARA, lalu jalankan ci/pipeline-local.sh dua kali:
#
#   1. jalur sah          -> exit 0, berkas penanda DEPLOYED ada, verify x3 OK
#   2. artefak diubah 1 B -> exit != 0, DEPLOYED TIDAK ada, verify x3 ARTIFACT_MISMATCH (exit 1)
#
# Lalu audit: tidak ada privkey di direktori kerja/output, dan temp file kunci sudah hilang.
#
#   bash ci/test-pipeline.sh <image-lokal> <registry>      # mis. sister-sign:dev localhost:5000
#
# Registry lokal: docker run -d -p 5000:5000 --name registry registry:2
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci/lib.sh
. "$here/lib.sh"

img="${1:?usage: ci/test-pipeline.sh <local-image> <registry-host:port>}"
registry="${2:?usage: ci/test-pipeline.sh <local-image> <registry-host:port>}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
export TMPDIR="$tmp/tmp" # temp file kunci dari sign-artifact.sh dibuat di sini -> bisa diaudit
mkdir -p "$TMPDIR"

echo "== push ke $registry untuk mendapatkan digest"
docker tag "$img" "$registry/sister-sign:test"
docker push --quiet "$registry/sister-sign:test" >/dev/null
ref="$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$registry/sister-sign:test" |
  grep -F "$registry/sister-sign@sha256:" | head -n1)"
require_digest_ref "$ref"
echo "image: $ref"

echo "== kunci + trust store sementara (bukan kunci demo CI)"
mkdir -p "$tmp/keys"
kdir="$(host_path "$tmp/keys")"
for spec in ed25519:demo-ed25519 ecdsa-p256-sha256:demo-ecdsa-p256 rsa-pss-sha256:demo-rsa-pss; do
  tool_run "$ref" -v "$kdir:/k" -- keygen -algorithm "${spec%%:*}" -out "/k/${spec#*:}" >/dev/null
  tool_run "$ref" -v "$kdir:/k" -- trust add -store /k/trust.json -key "/k/${spec#*:}.pub.pem" \
    -package sister-sign >/dev/null
done
export TRUST_STORE="$tmp/keys/trust.json"

fails=0
# check DESKRIPSI PERINTAH... : PASS bila perintah sukses.
check() {
  local desc="$1"
  shift
  if "$@"; then echo "PASS  $desc"; else
    echo "FAIL  $desc"
    fails=$((fails + 1))
  fi
}
# verify_result DIR NAMA EXIT STATUS : DIR/verify/NAMA.json tersimpan dengan exit code dan status itu
# (NAMA mis. verify-ed25519, sbom-verify-ed25519, sbom-check-ed25519).
verify_result() {
  [ "$(cat "$1/verify/$2.json.exit" 2>/dev/null)" = "$3" ] &&
    grep -q "\"status\":\"$4\"" "$1/verify/$2.json"
}
no_privkey_in_logs() { ! grep -qE -- "$PRIVKEY_PATTERN" "$@"; }
dir_empty() { [ -z "$(ls -A "$1")" ]; }

echo "== 1. jalur sah"
rc_ok=0
bash "$here/pipeline-local.sh" "$ref" "$tmp/keys" "$tmp/ok" >"$tmp/ok.log" 2>&1 || rc_ok=$?
sed 's/^/   | /' "$tmp/ok.log"
check "jalur sah: exit 0" test "$rc_ok" -eq 0
check "jalur sah: berkas penanda DEPLOYED ada" test -f "$tmp/ok/deploy/DEPLOYED"
for alg in ed25519 ecdsa-p256-sha256 rsa-pss-sha256; do
  check "jalur sah: verify $alg exit 0 + OK" verify_result "$tmp/ok" "verify-$alg" 0 OK
  check "jalur sah: sbom verify $alg exit 0 + OK" verify_result "$tmp/ok" "sbom-verify-$alg" 0 OK
  check "jalur sah: sbom check $alg exit 0 + OK" verify_result "$tmp/ok" "sbom-check-$alg" 0 OK
done
check "jalur sah: SBOM ikut di-deploy" test -f "$tmp/ok/deploy/sister-sign-linux-amd64.cdx.json"

echo "== 2. artefak diubah 1 byte setelah sign"
rc_bad=0
bash "$here/pipeline-local.sh" "$ref" "$tmp/keys" "$tmp/bad" --tamper >"$tmp/bad.log" 2>&1 || rc_bad=$?
sed 's/^/   | /' "$tmp/bad.log"
check "tamper: exit != 0" test "$rc_bad" -ne 0
check "tamper: berkas penanda DEPLOYED TIDAK ada" test ! -e "$tmp/bad/deploy/DEPLOYED"
for alg in ed25519 ecdsa-p256-sha256 rsa-pss-sha256; do
  check "tamper: verify $alg exit 1 + ARTIFACT_MISMATCH" verify_result "$tmp/bad" "verify-$alg" 1 ARTIFACT_MISMATCH
  check "tamper: sbom verify $alg tetap OK (SBOM utuh)" verify_result "$tmp/bad" "sbom-verify-$alg" 0 OK
  check "tamper: sbom check $alg exit 1 + ARTIFACT_MISMATCH" verify_result "$tmp/bad" "sbom-check-$alg" 1 ARTIFACT_MISMATCH
done

echo "== 3. audit privkey"
check "output kedua run tanpa privkey" bash "$here/audit-no-privkey.sh" "$tmp/ok" "$tmp/bad"
check "log kedua run tanpa privkey" no_privkey_in_logs "$tmp/ok.log" "$tmp/bad.log"
check "temp file kunci sudah dihapus" dir_empty "$TMPDIR"

echo
if [ "$fails" -ne 0 ]; then
  echo "test-pipeline: $fails cek GAGAL"
  exit 1
fi
echo "test-pipeline: semua cek lulus"
