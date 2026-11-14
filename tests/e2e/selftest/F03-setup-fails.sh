DESC="selftest: persiapan gagal (harus terdeteksi ERROR)"
EXPECT_EXIT=0
run() {
  must sis keygen -algorithm tidak-ada -out k
  verify_std
}
