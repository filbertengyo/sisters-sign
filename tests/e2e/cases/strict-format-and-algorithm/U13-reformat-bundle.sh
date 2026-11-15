DESC="U13: whitespace dan urutan field bundle diubah, kedua string Base64 tetap -> OK"
EXPECT_EXIT=0
EXPECT_STATUS=OK
EXPECT_JSON_LINE=1
run() {
  setup_signed ed25519
  forge reformat app.bundle.json reformatted.bundle.json
  check_differs app.bundle.json reformatted.bundle.json "teks bundle memang berbeda"
  forge extract-manifest app.bundle.json a.manifest
  forge extract-manifest reformatted.bundle.json b.manifest
  forge extract-signature app.bundle.json a.sig
  forge extract-signature reformatted.bundle.json b.sig
  check_same a.manifest b.manifest "byte manifest sama"
  check_same a.sig b.sig "byte signature sama"
  sis verify -file app.bin -bundle reformatted.bundle.json -trust-store t.json -package demo -version 1.0.0 -json
}
