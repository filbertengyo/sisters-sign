DESC="U10g: manifest melebihi 16 KiB (ditandatangani sah) -> FORMAT_ERROR"
EXPECT_EXIT=1
EXPECT_STATUS=FORMAT_ERROR
EXPECT_STDERR_CONTAINS="16 KiB"
run() {
  gen_key k ed25519
  make_file app.bin "isi artefak"
  trust_add t.json k.pub.pem demo
  {
    printf '%s' '{"schema":"minisign-manifest/v1","package":"demo","version":"'
    head -c 17000 /dev/zero | tr '\0' 'A'
    printf '%s' '","algorithm":"ed25519","keyid":"'"$KEYID"'","artifact":{"name":"app.bin","size":11,"sha256":"'"$(sha256_of app.bin)"'"}}'
  } >m.json
  check_eq "$([ "$(file_size m.json)" -gt 16384 ] && echo besar)" "besar" "manifest > 16 KiB"
  forge sign-manifest k.key.pem m.json forged.bundle.json
  sis verify -file app.bin -bundle forged.bundle.json -trust-store t.json -package demo -version 1.0.0
}
