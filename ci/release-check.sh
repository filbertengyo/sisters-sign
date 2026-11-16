#!/usr/bin/env bash
# Pemeriksaan sebelum rilis. Jalankan dari root repo:
#
#   bash ci/release-check.sh v0.1.0
#
# GAGAL (exit 1) bila:
#   - ada blok PEM privkey di commit mana pun (seluruh histori, semua ref) di luar lokasi kunci test
#     yang diizinkan (tests/unit/*.cpp, tests/fixtures/);
#   - ada berkas *.key.pem / *.p8 / *.p12 / *.pfx ter-track di luar tests/fixtures/;
#   - versi CMakeLists.txt, src/util/version.cpp, dan tag tidak sama.
# PERINGATAN (tetap exit 0) bila: laporan masih memuat \isi{...}, PDF laporan belum ada, atau
# digest di README belum diisi.
set -euo pipefail
# shellcheck source=ci/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

tag="${1:?usage: ci/release-check.sh <tag, mis. v0.1.0>}"
want="${tag#v}"
fails=0
warns=0
bad() {
  echo "FAIL  $*"
  fails=$((fails + 1))
}
warn() {
  echo "WARN  $*"
  warns=$((warns + 1))
}
ok() { echo "OK    $*"; }

allowed_key_path() { [[ "$1" =~ ^tests/unit/[^/]+\.cpp$ || "$1" == tests/fixtures/* ]]; }

echo "== privkey di seluruh histori git ($(git rev-list --all | wc -l | tr -d ' ') commit)"
paths="$(git rev-list --all | xargs -r git grep -lE -- "$PRIVKEY_PATTERN" 2>/dev/null |
  sed 's/^[0-9a-f]*://' | sort -u)"
found_bad=0
while IFS= read -r p; do
  [ -n "$p" ] || continue
  if allowed_key_path "$p"; then
    echo "      kunci test (diizinkan): $p"
  else
    bad "privkey di histori: $p"
    found_bad=1
  fi
done <<<"$paths"
[ "$found_bad" -eq 0 ] && ok "tidak ada privkey di luar lokasi kunci test"

echo "== berkas kunci ter-track"
keyfiles="$(git ls-files | grep -E '\.(key\.pem|p8|p12|pfx)$' | grep -v '^tests/fixtures/' || :)"
if [ -n "$keyfiles" ]; then bad "berkas kunci ter-track: $keyfiles"; else ok "tidak ada"; fi

echo "== versi"
cmake_ver="$(sed -n 's/^project(sister-sign VERSION \([0-9.]*\).*/\1/p' CMakeLists.txt)"
src_ver="$(sed -n 's/.*return "\([^"]*\)".*/\1/p' src/util/version.cpp)"
if [ "$cmake_ver" = "$want" ] && [ "$src_ver" = "$want" ]; then
  ok "CMakeLists.txt = version.cpp = tag = $want"
else
  bad "versi tidak sama: CMakeLists.txt=$cmake_ver version.cpp=$src_ver tag=$want"
fi

echo "== laporan"
if grep -rn --include='*.tex' '\\isi{' laporan/contents laporan/main.tex >/dev/null 2>&1; then
  warn "laporan masih memuat $(grep -rn --include='*.tex' '\\isi{' laporan/contents laporan/main.tex | wc -l | tr -d ' ') penanda \\isi{...}"
else
  ok "tidak ada \\isi{...}"
fi
pdf="$(find laporan -maxdepth 1 -name '*_Tugas3_IF4020.pdf' | head -n1)"
if [ -n "$pdf" ]; then ok "PDF: $pdf"; else warn "PDF laporan (NIM1_NIM2_NIM3_Tugas3_IF4020.pdf) belum ada di laporan/"; fi

echo "== README"
if grep -q 'diisi setelah tag di-push' README.md; then
  warn "tabel versi <-> tag <-> digest di README belum diisi"
else
  ok "tabel digest terisi"
fi

echo
echo "release-check: $fails gagal, $warns peringatan"
[ "$fails" -eq 0 ]
