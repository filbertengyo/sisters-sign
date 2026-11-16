#!/usr/bin/env bash
# SBOM CycloneDX 1.6 untuk artefak rilis: metadata.component = binary sister-sign beserta
# SHA-256-nya; components = pustaka runtime di image (versi dari dpkg di dalam image) dan glaze
# (header-only, terkompilasi ke dalam binary). Ditandatangani dengan `sister-sign sbom sign`.
#
#   bash ci/make-sbom.sh <image@digest> <binary> > sister-sign-linux-amd64.cdx.json
set -euo pipefail
# shellcheck source=ci/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

[ "$#" -eq 2 ] || die "usage: ci/make-sbom.sh <image@digest> <binary>"
ref="$1" binary="$2"
require_digest_ref "$ref"
[ -f "$binary" ] || die "binary tidak ada: $binary"

version="$(tool_run "$ref" -- -version)"
version="${version#sister-sign }"
sha="$(sha256sum "$binary" | cut -d' ' -f1)"
digest="${ref##*@}"
now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Versi paket runtime langsung dari image (bukan dari asumsi).
pkgs="$(docker run --rm --network none --entrypoint dpkg-query "$ref" \
  -W -f='${Package} ${Version}\n' libssl3t64 libstdc++6 libgcc-s1 libc6 </dev/null)"

components=""
while read -r name ver; do
  [ -n "$name" ] || continue
  components+="$(printf '{"type":"library","bom-ref":"pkg:deb/debian/%s@%s","name":"%s","version":"%s","purl":"pkg:deb/debian/%s@%s?arch=amd64&distro=debian-13","scope":"required"},' \
    "$name" "$ver" "$name" "$ver" "$name" "$ver")"
done <<<"$pkgs"
components+='{"type":"library","bom-ref":"pkg:github/stephenberry/glaze@v8.4.0","name":"glaze","version":"8.4.0","purl":"pkg:github/stephenberry/glaze@v8.4.0","scope":"required","description":"header-only JSON library, compiled into the binary"}'

cat <<EOF
{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"timestamp":"$now","tools":{"components":[{"type":"application","name":"ci/make-sbom.sh"}]},"component":{"type":"application","bom-ref":"sister-sign","name":"sister-sign","version":"$version","description":"sister-sign linux/amd64 executable","hashes":[{"alg":"SHA-256","content":"$sha"}],"purl":"pkg:github/filbertengyo/sisters-sign@v$version"},"properties":[{"name":"sister-sign:image","value":"$ref"},{"name":"sister-sign:image-digest","value":"$digest"}]},"components":[$components],"dependencies":[{"ref":"sister-sign","dependsOn":["pkg:github/stephenberry/glaze@v8.4.0"]}]}
EOF
