#!/usr/bin/env bash
# Bandingkan median dua run benchmark (T29: "jalankan 2x, median beda < 20%").
#
#   bash bench/compare.sh <run1/summary.csv> <run2/summary.csv> [batas-persen]
#
# Stdout: tabel markdown per operasi. Exit 0 bila semua selisih < batas (default 20), 1 bila ada
# yang melewati batas (penyebabnya harus dicatat di docs/benchmark.md), 2 bila pemakaian salah.
set -euo pipefail
[ "$#" -ge 2 ] || {
  echo "usage: bench/compare.sh <summary1.csv> <summary2.csv> [limit-percent]" >&2
  exit 2
}
limit="${3:-20}"
awk -F, -v limit="$limit" '
  FNR == 1 { next }
  NR == FNR { a[$1 FS $2 FS $3] = $5; order[++n] = $1 FS $2 FS $3; next }
  { b[$1 FS $2 FS $3] = $5 }
  END {
    print "| Operasi | Profil | Ukuran (B) | median run 1 (µs) | median run 2 (µs) | selisih | < " limit "% |"
    print "|---|---|---:|---:|---:|---:|:---:|"
    over = 0
    for (i = 1; i <= n; i++) {
      k = order[i]
      if (!(k in b)) { printf "| %s | (tidak ada di run 2) |\n", k; over++; continue }
      split(k, f, FS)
      d = (a[k] > 0) ? (b[k] - a[k]) / a[k] * 100 : 0
      ad = d < 0 ? -d : d
      ok = (ad < limit) ? "ya" : "**TIDAK**"
      if (ad >= limit) over++
      printf "| %s | %s | %s | %.3f | %.3f | %+.1f%% | %s |\n", f[1], f[2], f[3], a[k], b[k], d, ok
    }
    printf "\n%d dari %d baris selisih median >= %s%%.\n", over, n, limit
    exit over > 0 ? 1 : 0
  }
' "$1" "$2"
