DESC="U06b: kunci penerbit dihapus dari trust store (trust remove) -> KEY_NOT_TRUSTED"
EXPECT_EXIT=1
EXPECT_STATUS=KEY_NOT_TRUSTED
run() {
  setup_signed ed25519
  must sis verify -file app.bin -bundle app.bundle.json -trust-store t.json -package demo -version 1.0.0
  must sis trust remove -store t.json -keyid "$KEYID"
  verify_std
}
