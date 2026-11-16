DESC="S04: artefak rilis diganti (SBOM tetap sah) -> sbom check ARTIFACT_MISMATCH"
EXPECT_EXIT=1
EXPECT_STATUS=ARTIFACT_MISMATCH
. "$(dirname "${BASH_SOURCE[0]}")/_sbom.sh.inc"
run() {
  setup_sbom_signed
  must sis sbom verify -sbom app.cdx.json -bundle app.cdx.bundle.json -trust-store t.json \
    -package demo -version 1.0.0
  make_file app.bin "artefak pengganti"
  sis sbom check -sbom app.cdx.json -file app.bin -json
}
