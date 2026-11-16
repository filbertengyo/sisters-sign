DESC="S03: isi SBOM diubah setelah ditandatangani -> sbom verify ARTIFACT_MISMATCH"
EXPECT_EXIT=1
EXPECT_STATUS=ARTIFACT_MISMATCH
. "$(dirname "${BASH_SOURCE[0]}")/_sbom.sh.inc"
run() {
  setup_sbom_signed
  sed -i 's/"openssl"/"libressl"/' app.cdx.json
  sis sbom verify -sbom app.cdx.json -bundle app.cdx.bundle.json -trust-store t.json \
    -package demo -version 1.0.0 -json
}
