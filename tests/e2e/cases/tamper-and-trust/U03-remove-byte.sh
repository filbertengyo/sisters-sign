DESC="U03b: satu byte dihapus dari akhir artefak -> ARTIFACT_MISMATCH (ukuran)"
EXPECT_EXIT=1
EXPECT_STATUS=ARTIFACT_MISMATCH
EXPECT_STDERR_CONTAINS="ukuran"
run() {
  setup_signed ed25519
  head -c "$(($(file_size app.bin) - 1))" app.bin >app.tmp
  mv app.tmp app.bin
  verify_std
}
