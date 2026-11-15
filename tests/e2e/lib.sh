# Helper untuk berkas kasus e2e. Di-source oleh run.sh di dalam subshell per kasus; jangan dijalankan
# langsung. Kasus bekerja di direktori kerja yang bersih (cwd) sehingga semua path relatif.
#
# Variabel dari harness: SIS (path biner sister-sign), CASE_OUT (direktori hasil kasus ini).
#
# Perintah yang dinilai = pemanggilan `sis` TERAKHIR di dalam run(). Pemanggilan sebelumnya
# (persiapan) dibungkus `must` supaya kegagalannya terdeteksi sebagai ERROR, bukan lulus diam-diam.

# Jalankan sister-sign: stdin ditutup, stdout/stderr/exit code disimpan, perintah dicatat.
sis() {
  {
    printf 'sister-sign'
    printf ' %q' "$@"
    printf '\n'
  } >>"$CASE_OUT/commands.txt"
  "$SIS" "$@" </dev/null >"$CASE_OUT/last.out" 2>"$CASE_OUT/last.err"
  local rc=$?
  printf '%s\n' "$rc" >"$CASE_OUT/last.rc"
  return $rc
}

# must <perintah...>: hentikan kasus (ERROR) bila perintah persiapan gagal.
must() {
  "$@" || {
    printf 'persiapan gagal (rc=%s): %s\n' "$?" "$*" >"$CASE_OUT/setup_error.txt"
    exit 99
  }
}

# make_file NAMA ISI : tulis berkas tanpa newline akhir (isi dari argumen, deterministik).
make_file() { printf '%s' "$2" >"$1"; }

# make_bytes NAMA N : berkas N byte pola deterministik (untuk artefak biner/besar).
make_bytes() { head -c "$2" /dev/zero | tr '\0' 'A' >"$1"; }

# gen_key PREFIX ALGORITMA : buat PREFIX.key.pem dan PREFIX.pub.pem (kunci khusus test).

# trust_add STORE PUBKEY PACKAGE
trust_add() { must sis trust add -store "$1" -key "$2" -package "$3"; }

# sign_ok FILE PACKAGE VERSION KEY OUT
sign_ok() { must sis sign -file "$1" -package "$2" -version "$3" -key "$4" -out "$5"; }

# Skenario standar: kunci ALG, artefak app.bin, trust store t.json, bundle app.bundle.json.
# Setelah ini panggil `sis verify ...` sebagai perintah yang dinilai.
setup_signed() {
  local alg="${1:-ed25519}"
  gen_key k "$alg"
  make_file app.bin "isi artefak"
  trust_add t.json k.pub.pem demo
  sign_ok app.bin demo 1.0.0 k.key.pem app.bundle.json
}

# verify_std [-json] : verify dengan berkas skenario standar.
verify_std() {
  sis verify -file app.bin -bundle app.bundle.json -trust-store t.json -package demo \
    -version 1.0.0 "$@"
}

# ---- alat bantu untuk kasus U01-U14 -------------------------------------------------------------

# forge <perintah...> : alat bantu test (tests/tools/forge.cpp) untuk membuat/memanipulasi bundle.
# Selalu bagian persiapan: gagal = ERROR. Dicatat di setup.txt (bukan commands.txt).
forge() {
  {
    printf 'forge'
    printf ' %q' "$@"
    printf '\n'
  } >>"$CASE_OUT/setup.txt"
  "$FORGE" "$@" || {
    printf 'forge gagal: %s\n' "$*" >"$CASE_OUT/setup_error.txt"
    exit 99
  }
}

# gen_key juga menyimpan keyid yang dicetak keygen ke KEYID.
gen_key() {
  must sis keygen -algorithm "$2" -out "$1"
  KEYID="$(sed -n 's/^keyid: //p' "$CASE_OUT/last.out")"
}

# sha256_of BERKAS
sha256_of() { sha256sum "$1" | cut -d' ' -f1; }

# file_size BERKAS
file_size() { wc -c <"$1" | tr -d ' '; }

# manifest_text PACKAGE VERSION ALGORITMA KEYID NAMA UKURAN SHA256 : manifest kanonik (tanpa newline).
manifest_text() {
  printf '{"schema":"minisign-manifest/v1","package":"%s","version":"%s","algorithm":"%s","keyid":"%s","artifact":{"name":"%s","size":%s,"sha256":"%s"}}' \
    "$1" "$2" "$3" "$4" "$5" "$6" "$7"
}

# Pemeriksaan tambahan di luar perintah yang dinilai. Hasil masuk checks.txt; runner menjadikan kasus
# FAIL bila ada yang gagal dan mencatat jumlahnya di tabel.
#   check_same A B DESKRIPSI      isi berkas A dan B identik
#   check_differs A B DESKRIPSI   isi berkas A dan B berbeda
#   check_eq NILAI1 NILAI2 DESKRIPSI
check_same() {
  if cmp -s "$1" "$2"; then echo "PASS $3" >>"$CASE_OUT/checks.txt"; else echo "FAIL $3" >>"$CASE_OUT/checks.txt"; fi
}
check_differs() {
  if cmp -s "$1" "$2"; then echo "FAIL $3" >>"$CASE_OUT/checks.txt"; else echo "PASS $3" >>"$CASE_OUT/checks.txt"; fi
}
check_eq() {
  if [ "$1" = "$2" ]; then echo "PASS $3" >>"$CASE_OUT/checks.txt"; else echo "FAIL $3 ('$1' != '$2')" >>"$CASE_OUT/checks.txt"; fi
}

# make_binary NAMA : berkas 256 byte berisi semua nilai byte 0x00-0xFF (deterministik).
make_binary() {
  local i=0
  : >"$1"
  while [ "$i" -lt 256 ]; do
    printf "\$(printf '%03o' "$i")" >>"$1"
    i=$((i + 1))
  done
}

# make_empty NAMA : berkas kosong.
make_empty() { : >"$1"; }
