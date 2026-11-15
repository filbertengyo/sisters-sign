DESC="U10d: tipe data salah di bundle (signature_b64 berupa angka) -> FORMAT_ERROR"
EXPECT_EXIT=1
EXPECT_STATUS=FORMAT_ERROR
run() {
  setup_signed ed25519
  sed 's/"signature_b64":"[^"]*"/"signature_b64":12345/' app.bundle.json >bad.bundle.json
  check_differs app.bundle.json bad.bundle.json "bundle memang diubah"
  sis verify -file app.bin -bundle bad.bundle.json -trust-store t.json -package demo -version 1.0.0
}
