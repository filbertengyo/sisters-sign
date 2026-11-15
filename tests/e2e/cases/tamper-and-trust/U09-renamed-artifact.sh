DESC="U09: nama berkas artefak diubah, isi sama -> METADATA_MISMATCH"
EXPECT_EXIT=1
EXPECT_STATUS=METADATA_MISMATCH
EXPECT_STDERR_CONTAINS="nama artefak"
run() {
  setup_signed ed25519
  mv app.bin renamed.bin
  sis verify -file renamed.bin -bundle app.bundle.json -trust-store t.json -package demo -version 1.0.0
}
