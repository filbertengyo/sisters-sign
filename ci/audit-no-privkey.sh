#!/usr/bin/env bash
# Audit: pastikan direktori (artefak run, log job, isi image yang diekspor) tidak memuat
# privkey: tidak ada blok PEM privkey dan tidak ada berkas berekstensi kunci privat.
#
#   bash ci/audit-no-privkey.sh <dir>...
set -euo pipefail
# shellcheck source=ci/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

[ "$#" -ge 1 ] || die "usage: ci/audit-no-privkey.sh <dir>..."
bad=0
for dir in "$@"; do
  [ -d "$dir" ] || die "bukan direktori: $dir"
  files="$(find "$dir" -type f | wc -l | tr -d ' ')"
  # -a: berkas biner (mis. binary sister-sign) juga diperiksa sebagai teks.
  if hits="$(grep -rlaE -- "$PRIVKEY_PATTERN" "$dir")"; then
    echo "::error::blok PEM privkey ditemukan di: $hits"
    bad=1
  fi
  if keyfiles="$(find "$dir" -type f \( -name '*.key.pem' -o -name '*.p8' -o -name '*.p12' -o -name '*.pfx' \) | grep .)"; then
    echo "::error::berkas kunci privat ditemukan: $keyfiles"
    bad=1
  fi
  echo "diperiksa: $dir ($files berkas)"
done
[ "$bad" -eq 0 ] || exit 1
echo "OK: tidak ada privkey"
