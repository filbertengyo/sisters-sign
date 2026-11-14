DESC="selftest: exit code yang diharapkan salah (harus terdeteksi FAIL)"
EXPECT_EXIT=0
run() {
  setup_signed ed25519
  make_file app.bin "diubah"
  verify_std
}
