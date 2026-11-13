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
