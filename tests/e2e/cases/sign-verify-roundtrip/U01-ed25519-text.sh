DESC="U01 ed25519: berkas teks -> sign lalu verify OK"
EXPECT_EXIT=0
EXPECT_STATUS=OK
EXPECT_JSON_LINE=1
run() {
  gen_key k ed25519
  make_file app.bin "halo dunia, ini artefak teks
baris kedua"
  trust_add t.json k.pub.pem demo
  sign_ok app.bin demo 1.0.0 k.key.pem app.bundle.json
  verify_std -json
}
