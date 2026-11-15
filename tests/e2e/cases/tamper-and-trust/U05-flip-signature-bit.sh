DESC="U05: satu bit signature dibalik (panjang & Base64 tetap valid) -> INVALID_SIGNATURE"
EXPECT_EXIT=1
EXPECT_STATUS=INVALID_SIGNATURE
run() {
  setup_signed ed25519
  forge extract-signature app.bundle.json before.sig
  forge flip-sig-bit app.bundle.json flipped.bundle.json 0
  forge extract-signature flipped.bundle.json after.sig
  check_differs before.sig after.sig "signature memang berubah"
  check_eq "$(file_size before.sig)" "$(file_size after.sig)" "panjang signature sama"
  sis verify -file app.bin -bundle flipped.bundle.json -trust-store t.json -package demo -version 1.0.0
}
