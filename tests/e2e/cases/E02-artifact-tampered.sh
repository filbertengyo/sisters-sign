DESC="artefak diubah setelah sign -> ARTIFACT_MISMATCH"
EXPECT_EXIT=1
EXPECT_STATUS=ARTIFACT_MISMATCH
EXPECT_STDOUT_EMPTY=1
run() {
  setup_signed ed25519
  make_file app.bin "isi artefak diubah"
  verify_std
}
