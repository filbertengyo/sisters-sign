DESC="U06a: trust store kosong -> KEY_NOT_TRUSTED"
EXPECT_EXIT=1
EXPECT_STATUS=KEY_NOT_TRUSTED
run() {
  setup_signed ed25519
  printf '%s' '{"schema":"minisign-trust/v1","keys":[]}' >empty.json
  sis verify -file app.bin -bundle app.bundle.json -trust-store empty.json -package demo -version 1.0.0
}
