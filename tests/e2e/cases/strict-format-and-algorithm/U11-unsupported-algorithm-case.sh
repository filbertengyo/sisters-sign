DESC="U11b: algorithm berbeda huruf besar (ED25519) tidak dianggap profil sah -> UNSUPPORTED_ALGORITHM"
EXPECT_EXIT=1
EXPECT_STATUS=UNSUPPORTED_ALGORITHM
run() {
  gen_key k ed25519
  make_file app.bin "isi artefak"
  trust_add t.json k.pub.pem demo
  manifest_text demo 1.0.0 ED25519 "$KEYID" app.bin "$(file_size app.bin)" "$(sha256_of app.bin)" >m.json
  forge sign-manifest k.key.pem m.json forged.bundle.json
  sis verify -file app.bin -bundle forged.bundle.json -trust-store t.json -package demo -version 1.0.0
}
