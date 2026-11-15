DESC="U01 ecdsa-p256-sha256: berkas kosong (0 byte) -> sign lalu verify OK"
EXPECT_EXIT=0
EXPECT_STATUS=OK
EXPECT_JSON_LINE=1
run() {
  gen_key k ecdsa-p256-sha256
  make_empty app.bin
  trust_add t.json k.pub.pem demo
  sign_ok app.bin demo 1.0.0 k.key.pem app.bundle.json
  verify_std -json
}
