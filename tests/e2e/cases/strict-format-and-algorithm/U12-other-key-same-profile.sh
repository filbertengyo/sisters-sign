DESC="U12: ditandatangani kunci lain (profil sama, keyid sesuai kunci itu) yang tidak di-trust -> KEY_NOT_TRUSTED"
EXPECT_EXIT=1
EXPECT_STATUS=KEY_NOT_TRUSTED
run() {
  gen_key trusted ed25519
  gen_key rogue ed25519
  check_eq "$KEYID" "$(sed -n 's/^keyid: //p' "$CASE_OUT/last.out")" "keyid kunci rogue dicatat"
  make_file app.bin "isi artefak"
  trust_add t.json trusted.pub.pem demo
  sign_ok app.bin demo 1.0.0 rogue.key.pem app.bundle.json
  verify_std
}
