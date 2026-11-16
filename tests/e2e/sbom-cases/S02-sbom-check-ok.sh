DESC="S02: artefak sesuai SHA-256 di SBOM -> sbom check OK"
EXPECT_EXIT=0
EXPECT_STATUS=OK
EXPECT_JSON_LINE=1
. "$(dirname "${BASH_SOURCE[0]}")/_sbom.sh.inc"
run() {
  setup_sbom_signed
  must sis sbom verify -sbom app.cdx.json -bundle app.cdx.bundle.json -trust-store t.json \
    -package demo -version 1.0.0
  sis sbom check -sbom app.cdx.json -file app.bin -json
}
