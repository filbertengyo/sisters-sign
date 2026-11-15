DESC="U07: kunci hanya diizinkan untuk paket lain -> KEY_NOT_TRUSTED"
EXPECT_EXIT=1
EXPECT_STATUS=KEY_NOT_TRUSTED
run() {
  gen_key k ed25519
  make_file app.bin "isi artefak"
  trust_add t.json k.pub.pem paket-lain
  sign_ok app.bin demo 1.0.0 k.key.pem app.bundle.json
  verify_std
}
