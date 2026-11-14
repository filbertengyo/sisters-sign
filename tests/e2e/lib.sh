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
gen_key() { must sis keygen -algorithm "$2" -out "$1"; }

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
