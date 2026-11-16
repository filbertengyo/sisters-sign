DESC="S05: SBOM tanpa SHA-256 artefak -> sbom sign ditolak (exit 2), bundle tidak dibuat"
EXPECT_EXIT=2
EXPECT_STDERR_CONTAINS="SHA-256"
. "$(dirname "${BASH_SOURCE[0]}")/_sbom.sh.inc"
run() {
  gen_key k ed25519
  make_sbom demo 1.0.0 '{"alg":"SHA-1","content":"da39a3ee5e6b4b0d3255bfef95601890afd80709"}'
  sis sbom sign -sbom app.cdx.json -package demo -version 1.0.0 -key k.key.pem \
    -out app.cdx.bundle.json
  check_eq "$([ -e app.cdx.bundle.json ] && echo ada || echo tidak)" tidak "bundle tidak dibuat"
}
