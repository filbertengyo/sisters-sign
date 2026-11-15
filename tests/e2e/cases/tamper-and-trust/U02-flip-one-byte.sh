DESC="U02: satu byte artefak diubah (ukuran & nama sama) -> ARTIFACT_MISMATCH"
EXPECT_EXIT=1
EXPECT_STATUS=ARTIFACT_MISMATCH
EXPECT_STDERR_CONTAINS="SHA-256"
run() {
  setup_signed ed25519
  before="$(file_size app.bin)"
  printf 'X' | dd of=app.bin bs=1 seek=0 conv=notrunc 2>/dev/null
  check_eq "$before" "$(file_size app.bin)" "ukuran artefak tidak berubah"
  verify_std
}
