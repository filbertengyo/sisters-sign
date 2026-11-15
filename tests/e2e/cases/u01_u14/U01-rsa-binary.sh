DESC="U01 rsa-pss-sha256: berkas biner (256 nilai byte) -> sign lalu verify OK"
EXPECT_EXIT=0
EXPECT_STATUS=OK
EXPECT_JSON_LINE=1
run() {
  gen_key k rsa-pss-sha256
  make_binary app.bin
  trust_add t.json k.pub.pem demo
  sign_ok app.bin demo 1.0.0 k.key.pem app.bundle.json
  verify_std -json
}
