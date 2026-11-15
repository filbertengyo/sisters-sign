DESC="U14 rsa-pss-sha256: sign manifest identik 2x -> signature BERBEDA (salt PSS acak); kedua bundle verify OK"
EXPECT_EXIT=0
EXPECT_STATUS=OK
run() {
  gen_key k rsa-pss-sha256
  make_file app.bin "isi artefak"
  trust_add t.json k.pub.pem demo
  sign_ok app.bin demo 1.0.0 k.key.pem a.bundle.json
  sign_ok app.bin demo 1.0.0 k.key.pem b.bundle.json
  forge extract-manifest a.bundle.json a.manifest
  forge extract-manifest b.bundle.json b.manifest
  forge extract-signature a.bundle.json a.sig
  forge extract-signature b.bundle.json b.sig
  check_same a.manifest b.manifest "manifest identik byte-per-byte"
  check_differs a.sig b.sig "signature BERBEDA (salt PSS acak)"
  must sis verify -file app.bin -bundle a.bundle.json -trust-store t.json -package demo -version 1.0.0
  sis verify -file app.bin -bundle b.bundle.json -trust-store t.json -package demo -version 1.0.0 -json
}
