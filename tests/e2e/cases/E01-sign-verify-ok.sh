DESC="sign lalu verify artefak utuh (Ed25519)"
EXPECT_EXIT=0
EXPECT_STATUS=OK
EXPECT_JSON_LINE=1
run() {
  setup_signed ed25519
  verify_std -json
}
