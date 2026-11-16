DESC="S01: SBOM ditandatangani (sbom sign) -> sbom verify OK"
EXPECT_EXIT=0
EXPECT_STATUS=OK
EXPECT_JSON_LINE=1
. "$(dirname "${BASH_SOURCE[0]}")/_sbom.sh.inc"
run() {
  setup_sbom_signed
  sis sbom verify -sbom app.cdx.json -bundle app.cdx.bundle.json -trust-store t.json \
    -package demo -version 1.0.0 -json
}
