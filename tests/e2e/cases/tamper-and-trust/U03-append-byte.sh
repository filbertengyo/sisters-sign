DESC="U03a: satu byte ditambahkan di akhir artefak -> ARTIFACT_MISMATCH (ukuran)"
EXPECT_EXIT=1
EXPECT_STATUS=ARTIFACT_MISMATCH
EXPECT_STDERR_CONTAINS="ukuran"
run() {
  setup_signed ed25519
  printf 'X' >>app.bin
  verify_std
}
