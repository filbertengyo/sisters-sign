DESC="artefak tidak ada -> INPUT_ERROR (exit 2)"
EXPECT_EXIT=2
EXPECT_STATUS=INPUT_ERROR
run() {
  setup_signed ed25519
  rm app.bin
  verify_std
}
