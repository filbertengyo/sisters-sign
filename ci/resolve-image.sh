#!/usr/bin/env bash
# Tahap Persiapan: pull image sister-sign BY DIGEST dan pastikan yang terpasang memang image
# dengan digest itu. Tag (`:latest`, `:0.1.0`) ditolak karena bisa dipindah ke image lain.
#
#   bash ci/resolve-image.sh <repo>@sha256:<digest>
#
# Stdout baris terakhir: `version=<versi>` (dari `sister-sign -version`).
set -euo pipefail
# shellcheck source=ci/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

ref="${1:?usage: ci/resolve-image.sh <repo>@sha256:<digest>}"
require_digest_ref "$ref"
repo="${ref%@*}"
digest="${ref##*@}"
# repo:tag@digest -> yang berlaku digest-nya; buang tag (tapi jangan port registry, mis. host:5000/x).
last="${repo##*/}"
[[ "$last" == *:* ]] && repo="${repo%:*}"

docker pull --quiet "$ref" >&2

# RepoDigests berisi <repo>@<digest> untuk tiap repo asal image ini; digest yang diminta harus ada.
docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$ref" | grep -qxF "$repo@$digest" ||
  die "digest image lokal tidak cocok dengan $ref"

out="$(tool_run "$ref" -- -version)"
[[ "$out" =~ ^sister-sign\ ([A-Za-z0-9][A-Za-z0-9._+-]{0,63})$ ]] ||
  die "output -version tidak terduga: '$out'"
echo "image OK: $ref ($out)" >&2
echo "version=${BASH_REMATCH[1]}"
