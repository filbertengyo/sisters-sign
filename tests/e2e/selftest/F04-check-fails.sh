DESC="selftest: perintah lulus tetapi pemeriksaan tambahan gagal (harus terdeteksi FAIL)"
EXPECT_EXIT=0
EXPECT_STATUS=OK
run() {
  setup_signed ed25519
  make_file a.txt "satu"
  make_file b.txt "dua"
  check_same a.txt b.txt "berkas ini sengaja berbeda"
  verify_std
}
