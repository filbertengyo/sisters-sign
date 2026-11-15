DESC="U10c: tipe data salah di manifest (size berupa string) -> FORMAT_ERROR"
EXPECT_EXIT=1
EXPECT_STATUS=FORMAT_ERROR
run() {
  gen_key k ed25519
  make_file app.bin "isi artefak"
  trust_add t.json k.pub.pem demo
  printf '%s' '{"schema":"minisign-manifest/v1","package":"demo","version":"1.0.0","algorithm":"ed25519","keyid":"'"$KEYID"'","artifact":{"name":"app.bin","size":"11","sha256":"'"$(sha256_of app.bin)"'"}}' >m.json
  forge sign-manifest k.key.pem m.json forged.bundle.json
  sis verify -file app.bin -bundle forged.bundle.json -trust-store t.json -package demo -version 1.0.0
}
