#!/usr/bin/env bash
# Cek image sister-sign (T25). Dipakai .github/workflows/build-image.yml; bisa juga lokal.
#
#   bash ci/check-image.sh <image-ref> [expected-version]
#
# <image-ref> boleh tag (sister-sign:dev) atau digest (ghcr.io/owner/repo@sha256:...).
set -euo pipefail
export MSYS_NO_PATHCONV=1  # Git Bash di Windows: jangan ubah path container (/work, /bin/cat)

img="${1:?usage: ci/check-image.sh <image-ref> [expected-version]}"
want="${2:-}"
fail() {
  echo "FAIL: $*" >&2
  exit 1
}

echo "== -version: --network none, uid sembarang, rootfs read-only, tanpa capability"
out="$(docker run --rm --network none --user 4242:4242 --read-only --cap-drop ALL \
  --security-opt no-new-privileges "$img" -version)"
echo "$out"
[[ "$out" == "sister-sign "* ]] || fail "output -version tidak terduga: $out"
if [[ -n "$want" && "$out" != "sister-sign $want" ]]; then
  echo "::warning::versi binary ($out) != versi yang diharapkan ($want)"
fi

echo "== user default bukan root"
user="$(docker image inspect --format '{{.Config.User}}' "$img")"
uid="${user%%:*}"
[[ -n "$uid" && "$uid" != "0" && "$uid" != "root" ]] || fail "image jalan sebagai root (User='$user')"
echo "User=$user"

echo "== input bind-mount :ro dengan --user \$(id -u):\$(id -g)"
tmp="$(mktemp -d)"
cid=""
cleanup() {
  chmod -R u+rwX "$tmp" 2>/dev/null || true
  rm -rf "$tmp"
  if [[ -n "$cid" ]]; then docker rm -f "$cid" >/dev/null; fi
}
trap cleanup EXIT
echo "probe" >"$tmp/artifact.txt"
chmod 0755 "$tmp"
chmod 0644 "$tmp/artifact.txt"
src="$tmp"
if command -v cygpath >/dev/null; then src="$(cygpath -w "$tmp")"; fi
docker run --rm --network none --user "$(id -u):$(id -g)" -v "$src:/work:ro" "$img" -version
[[ "$(docker run --rm --network none --user "$(id -u):$(id -g)" -v "$src:/work:ro" \
  --entrypoint /bin/cat "$img" /work/artifact.txt)" == "probe" ]] || fail "input :ro tidak terbaca"
# Tulis sebagai root: kalau mount ternyata rw, root pasti bisa menulis -> ketahuan.
if docker run --rm --network none --user 0:0 -v "$src:/work:ro" --entrypoint /bin/sh "$img" \
  -c 'echo x >/work/w' 2>/dev/null; then
  fail "mount :ro ternyata bisa ditulis"
fi

# Roundtrip fungsional (finalisasi T25 setelah T20). Pola mount sama dengan pipeline: input :ro,
# hanya direktori output yang bisa ditulis, rootfs read-only, tanpa jaringan, uid pemanggil.
# Kunci yang dipakai dibuat di sini (kunci test sementara) dan dihapus bersama $tmp.
run_tool() {
  docker run --rm --network none --user "$(id -u):$(id -g)" --read-only --cap-drop ALL \
    --security-opt no-new-privileges "$@" </dev/null
}
hostp() { if command -v cygpath >/dev/null; then cygpath -w "$1"; else printf '%s\n' "$1"; fi; }
rt="$tmp/roundtrip"
mkdir -p "$rt/keys" "$rt/out" "$rt/tampered"
printf 'Probe\n' >"$rt/tampered/artifact.txt" # nama & ukuran sama, 1 byte beda: harus ditolak
for alg in ed25519 ecdsa-p256-sha256 rsa-pss-sha256; do
  echo "== roundtrip $alg: keygen -> trust add -> sign (input :ro) -> verify -json"
  run_tool -v "$(hostp "$rt/keys"):/keys" "$img" keygen -algorithm "$alg" -out "/keys/$alg" >/dev/null ||
    fail "keygen $alg gagal"
  run_tool -v "$(hostp "$rt/keys"):/keys" "$img" trust add -store /keys/trust.json \
    -key "/keys/$alg.pub.pem" -package probe >/dev/null || fail "trust add $alg gagal"
  run_tool -v "$src:/work:ro" -v "$(hostp "$rt/keys"):/keys:ro" -v "$(hostp "$rt/out"):/out" "$img" \
    sign -file /work/artifact.txt -package probe -version 1.0.0 -key "/keys/$alg.key.pem" \
    -out "/out/$alg.bundle.json" >/dev/null || fail "sign $alg gagal"
  set +e
  json="$(run_tool -v "$src:/work:ro" -v "$(hostp "$rt/keys"):/keys:ro" -v "$(hostp "$rt/out"):/out:ro" \
    "$img" verify -file /work/artifact.txt -bundle "/out/$alg.bundle.json" -trust-store /keys/trust.json \
    -package probe -version 1.0.0 -json 2>/dev/null)"
  rc=$?
  set -e
  echo "   exit=$rc $json"
  [[ "$rc" -eq 0 && "$json" == '{"valid":true,"status":"OK",'*'"algorithm":"'"$alg"'"'* ]] ||
    fail "verify $alg tidak OK"

  echo "== roundtrip $alg: artefak diubah -> verify harus exit 1 (ARTIFACT_MISMATCH)"
  set +e
  json="$(run_tool -v "$(hostp "$rt/tampered"):/work:ro" -v "$(hostp "$rt/keys"):/keys:ro" \
    -v "$(hostp "$rt/out"):/out:ro" "$img" verify -file /work/artifact.txt \
    -bundle "/out/$alg.bundle.json" -trust-store /keys/trust.json -package probe -version 1.0.0 \
    -json 2>/dev/null)"
  rc=$?
  set -e
  echo "   exit=$rc $json"
  [[ "$rc" -eq 1 && "$json" == '{"valid":false,"status":"ARTIFACT_MISMATCH",'* ]] ||
    fail "verify $alg atas artefak yang diubah tidak ditolak dengan benar"
done
rm -rf "$rt"

echo "== docker history tidak memuat kunci"
if docker history --no-trunc "$img" | grep -Ei 'PRIVATE KEY|\.pem\b|\.key\b|\.p12\b|\.pfx\b'; then
  fail "docker history menyebut kunci"
fi

echo "== filesystem image tidak memuat private key"
cid="$(docker create "$img")"
root="$tmp/rootfs"
mkdir -p "$root"
docker export "$cid" | tar -x -C "$root" --exclude='dev/*' 2>/dev/null || true
chmod -R u+rwX "$root"
# Hanya berkas teks (-I): PEM key selalu teks; string header di dalam .so (mis. libgnutls)
# bukan kunci.
hits="$(grep -rIlE -- '-----BEGIN [A-Z ]*PRIVATE KEY-----' "$root" | sed "s#^$root##" || true)"
[[ -z "$hits" ]] || fail "ditemukan PEM private key: $hits"
keyfiles="$(docker export "$cid" | tar -t | grep -Ei '\.(pem|key|p8|p12|pfx)$' || true)"
[[ -z "$keyfiles" ]] || fail "ditemukan berkas kunci: $keyfiles"

size="$(docker image inspect --format '{{.Size}}' "$img")"
echo "== OK: $img (Size=${size} byte)"
