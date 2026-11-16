#!/usr/bin/env bash
# Bangun dokumentasi API: Doxygen + tema doxygen-awesome-css (versi dipin + checksum).
#
#   bash docs/api/build.sh [dir-output]      # default build/docs -> build/docs/html/index.html
#
# Butuh: doxygen (>= 1.9.5), curl, tar, sha256sum. Gagal bila ada peringatan dokumentasi.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

out="${1:-build/docs}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"

awesome_version=2.3.4
awesome_sha256=54d515327b559cd18c6f4d3e8a46e0facc635be1967fb69526f977285922960e
awesome_dir="$out/.cache/doxygen-awesome-css-$awesome_version"
if [ ! -f "$awesome_dir/doxygen-awesome.css" ]; then
  mkdir -p "$out/.cache"
  tarball="$out/.cache/doxygen-awesome-css-$awesome_version.tar.gz"
  curl -fsSL -o "$tarball" \
    "https://github.com/jothepro/doxygen-awesome-css/archive/refs/tags/v$awesome_version.tar.gz"
  echo "$awesome_sha256  $tarball" | sha256sum -c --quiet -
  tar -xzf "$tarball" -C "$out/.cache"
fi

version="$(sed -n 's/.*return "\([^"]*\)";.*/\1/p' src/util/version.cpp)"
[ -n "$version" ] || {
  echo "versi tidak ditemukan di src/util/version.cpp" >&2
  exit 1
}

rm -rf "$out/html"
echo "doxygen $(doxygen --version), doxygen-awesome-css $awesome_version, sister-sign $version"
SISTER_SIGN_VERSION="$version" DOCS_OUT="$out" AWESOME_DIR="$awesome_dir" doxygen docs/api/Doxyfile
touch "$out/html/.nojekyll" # GitHub Pages: sajikan berkas berawalan _ apa adanya
echo "dokumentasi: $out/html/index.html"
