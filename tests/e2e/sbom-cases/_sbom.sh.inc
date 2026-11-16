# Helper bersama kasus SBOM (di-source oleh tiap kasus; bukan kasus, karena tidak berakhiran .sh).
# make_sbom NAMA VERSI HASHES : SBOM CycloneDX minimal ke app.cdx.json.
make_sbom() {
  printf '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"component":{"type":"application","name":"%s","version":"%s","hashes":[%s]}},"components":[{"type":"library","name":"openssl","version":"3.5.7"}]}' \
    "$1" "$2" "$3" >app.cdx.json
}
sha_entry() { printf '{"alg":"SHA-256","content":"%s"}' "$1"; }
# Skenario standar: kunci ed25519 k.*, trust store t.json (package demo), artefak app.bin,
# SBOM app.cdx.json yang memuat SHA-256 app.bin, ditandatangani ke app.cdx.bundle.json.
setup_sbom_signed() {
  gen_key k ed25519
  trust_add t.json k.pub.pem demo
  make_file app.bin "isi artefak rilis"
  make_sbom demo 1.0.0 "$(sha_entry "$(sha256_of app.bin)")"
  must sis sbom sign -sbom app.cdx.json -package demo -version 1.0.0 -key k.key.pem \
    -out app.cdx.bundle.json
}
