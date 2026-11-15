DESC="U04: versi di manifest diubah (kanonik tetap), signature lama dipakai -> INVALID_SIGNATURE"
EXPECT_EXIT=1
EXPECT_STATUS=INVALID_SIGNATURE
run() {
  setup_signed ed25519
  forge extract-manifest app.bundle.json m.json
  sed 's/"version":"1.0.0"/"version":"1.0.1"/' m.json >m2.json
  check_differs m.json m2.json "manifest memang berubah"
  forge replace-manifest app.bundle.json m2.json forged.bundle.json
  # -version 1.0.1 cocok dengan manifest baru, jadi penyebab penolakan murni tanda tangan.
  sis verify -file app.bin -bundle forged.bundle.json -trust-store t.json -package demo -version 1.0.1
}
