DESC="selftest: status yang diharapkan salah (harus terdeteksi FAIL)"
EXPECT_EXIT=1
EXPECT_STATUS=KEY_NOT_TRUSTED
run() {
  setup_signed ed25519
  make_file app.bin "diubah"
  verify_std
}
