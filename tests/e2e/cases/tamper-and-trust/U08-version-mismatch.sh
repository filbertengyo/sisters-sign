DESC="U08: bundle sah, nama paket sesuai, versi input berbeda dari manifest -> METADATA_MISMATCH"
EXPECT_EXIT=1
EXPECT_STATUS=METADATA_MISMATCH
EXPECT_STDERR_CONTAINS="version"
run() {
  setup_signed ed25519
  sis verify -file app.bin -bundle app.bundle.json -trust-store t.json -package demo -version 2.0.0
}
