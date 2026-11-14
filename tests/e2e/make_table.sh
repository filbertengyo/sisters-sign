#!/usr/bin/env bash
# Ubah results.tsv (id, deskripsi, perintah, diharapkan, aktual, hasil) menjadi tabel markdown.
#   make_table.sh <results.tsv> > results.md
set -eu
[ "$#" -eq 1 ] || {
  echo "usage: $0 <results.tsv>" >&2
  exit 2
}

awk -F '\t' '
function esc(s) { gsub(/\|/, "\\|", s); return s }
BEGIN {
  print "| ID | Deskripsi | Perintah | Diharapkan | Aktual | Hasil |"
  print "|---|---|---|---|---|---|"
}
{
  printf "| %s | %s | `%s` | %s | %s | %s |\n", esc($1), esc($2), esc($3), esc($4), esc($5), esc($6)
}' "$1"
