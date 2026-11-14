DESC="selftest: kasus yang memang lulus"
EXPECT_EXIT=0
EXPECT_STATUS=OK
run() {
  setup_signed ed25519
  verify_std
}
