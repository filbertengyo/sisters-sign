DESC="U10b: field duplikat di JSON bundle -> FORMAT_ERROR"
EXPECT_EXIT=1
EXPECT_STATUS=FORMAT_ERROR
EXPECT_STDERR_CONTAINS="key ganda"
run() {
  setup_signed ed25519
  sed 's/}$/,"schema":"minisign-bundle\/v1"}/' app.bundle.json >dup.bundle.json
  check_differs app.bundle.json dup.bundle.json "bundle memang diubah"
  sis verify -file app.bin -bundle dup.bundle.json -trust-store t.json -package demo -version 1.0.0
}
