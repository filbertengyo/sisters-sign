#!/usr/bin/env bash
# Artefak rilis untuk pipeline contoh (T26): binary sister-sign itu sendiri, diambil dari image
# yang sudah di-pull by digest. Jadi yang ditandatangani persis binary yang dirilis.
#
#   bash ci/extract-binary.sh <repo>@sha256:<digest> <dir-output>
#
# Stdout: name=..., version=..., sha256=..., size=... (siap ditambahkan ke $GITHUB_OUTPUT).
set -euo pipefail
# shellcheck source=ci/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

ref="${1:?usage: ci/extract-binary.sh <image@digest> <out-dir>}"
outdir="${2:?usage: ci/extract-binary.sh <image@digest> <out-dir>}"
require_digest_ref "$ref"

name="sister-sign-linux-amd64"
mkdir -p "$outdir"
cid="$(docker create "$ref")"
trap 'docker rm -f "$cid" >/dev/null' EXIT
# Lewat stream tar (bukan path tujuan) supaya sama di Linux dan Docker Desktop Windows.
docker cp "$cid:/usr/local/bin/sister-sign" - | tar -x -O sister-sign >"$outdir/$name"
chmod 0755 "$outdir/$name"
[ -s "$outdir/$name" ] || die "binary tidak terambil dari image"

out="$(tool_run "$ref" -- -version)"
version="${out#sister-sign }"
sha="$(sha256sum "$outdir/$name" | cut -d' ' -f1)"
size="$(wc -c <"$outdir/$name" | tr -d ' ')"
echo "artefak: $outdir/$name ($size byte, sha256 $sha, versi $version)" >&2
printf 'name=%s\nversion=%s\nsha256=%s\nsize=%s\n' "$name" "$version" "$sha" "$size"
