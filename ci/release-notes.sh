#!/usr/bin/env bash
# Catatan rilis untuk draft GitHub Release (T36), dibuat dari hasil deploy yang sudah terverifikasi.
#
#   bash ci/release-notes.sh <tag> <versi> <image@digest> <dir-deploy>
set -euo pipefail
# shellcheck source=ci/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

[ "$#" -eq 4 ] || die "usage: ci/release-notes.sh <tag> <version> <image@digest> <deploy-dir>"
tag="$1" version="$2" ref="$3" deploy="$4"
repo="${ref%@*}"
digest="${ref##*@}"
artifact="$(sed -n 's/^artifact=//p' "$deploy/DEPLOYED")"
sha="$(sed -n 's/^sha256=//p' "$deploy/DEPLOYED")"

cat <<EOF
## sister-sign $version

Tanda tangan digital artefak perangkat lunak (Ed25519, ECDSA P-256, RSA-PSS 3072) dengan
manifest kanonik, bundle, dan trust store. Laporan: lampiran PDF di rilis ini.

### Image container (linux/amd64)

| Versi | Git tag | Image tag | Digest |
|---|---|---|---|
| $version | \`$tag\` | \`$repo:$version\` | \`$digest\` |

\`\`\`sh
docker pull $ref
docker run --rm --network none $ref -version
\`\`\`

Selalu pakai **digest**, bukan tag.

### Berkas

| Berkas | Isi |
|---|---|
| \`$artifact\` | binary Linux amd64 (diambil dari image di atas), sha256 \`$sha\` |
| \`$artifact.<algoritma>.bundle.json\` | bundle tanda tangan binary, satu per profil (kunci DEMO) |
| \`$artifact.cdx.json\` | SBOM CycloneDX 1.6 yang memuat SHA-256 binary |
| \`$artifact.cdx.json.<algoritma>.bundle.json\` | bundle tanda tangan SBOM (format bundle yang sama) |
| \`verify-*.json\`, \`sbom-verify-*.json\`, \`sbom-check-*.json\` | hasil \`verify -json\`, \`sbom verify -json\`, \`sbom check -json\` di pipeline |
| \`trust-store.json\` | trust store demo (sama dengan \`ci/trust-store.json\`) |
| \`DEPLOYED\`, \`SHA256SUMS\`, \`image-digest.txt\` | penanda deploy, checksum, digest image |

Verifikasi binary yang diunduh (butuh image di atas):

\`\`\`sh
docker run --rm --network none -v "\$PWD:/work:ro" $ref verify \\
  -file /work/$artifact -bundle /work/$artifact.ed25519.bundle.json \\
  -trust-store /work/trust-store.json -package sister-sign -version $version -json
\`\`\`

SBOM: verifikasi tanda tangannya, lalu keterikatannya dengan binary:

\`\`\`sh
docker run --rm --network none -v "\$PWD:/work:ro" $ref sbom verify \\
  -sbom /work/$artifact.cdx.json -bundle /work/$artifact.cdx.json.ed25519.bundle.json \\
  -trust-store /work/trust-store.json -package sister-sign -version $version -json
docker run --rm --network none -v "\$PWD:/work:ro" $ref sbom check \\
  -sbom /work/$artifact.cdx.json -file /work/$artifact -json
\`\`\`

Kunci di \`trust-store.json\` adalah kunci **demo** untuk tugas ini (privkey hanya ada di CI secret),
bukan kunci produksi.
EOF
