#!/usr/bin/env bash
# Uji integrasi CI/CD C01-C05 (spek Bagian 2.9 / Tabel 2.15) terhadap image rilis BY DIGEST.
# Program tidak dipasang dari source: semua sign/verify/trust jalan di container image itu, lewat
# skrip pipeline yang sama dengan release-pipeline.yml (ci/*.sh).
#
#   DEMO_KEY_ED25519=... DEMO_KEY_ECDSA_P256=... DEMO_KEY_RSA_PSS=... \
#     bash tests/integration/run.sh <image@digest> <dir-output>
#
#   DEMO_KEY_*   isi PEM PKCS#8 kunci demo (CI secret); tiap sign menulisnya ke temp file 0600
#                lalu menghapusnya (ci/sign-artifact.sh). Tidak pernah ditulis ke <dir-output>.
#   TRUST_STORE  (opsional) pengganti ci/trust-store.json, mis. kunci sementara di selftest.sh.
#
# Skenario (masing-masing di <dir-output>/<ID>-<nama>/ yang baru dan kosong):
#   C01  sign + verify + deploy (berkas penanda) x3 algoritma     -> exit 0, OK, DEPLOYED ada
#   C02  1 byte artefak diubah setelah sign (ukuran + nama sama)   -> exit 1, ARTIFACT_MISMATCH
#   C03  trust store kosong / kunci hanya dipercaya untuk package lain -> exit 1, KEY_NOT_TRUSTED
#   C04  path artefak tidak ada                                    -> exit 2, INPUT_ERROR
#   C05  image dijalankan dengan UID/GID runner, tanpa TTY, --network none (diperiksa + dijalankan)
# Skenario negatif lewat gerbang yang sama dengan pipeline: deploy HANYA bila verify exit 0, dan
# yang dinilai adalah exit code ASLI sister-sign (<dir>/verify/verify.json.exit), lalu status JSON,
# lalu ada/tidaknya <dir>/deploy/DEPLOYED.
#
# Hasil: <dir-output>/results.md (tabel), per skenario result.txt, commands.txt (perintah docker
# run persis), verify/verify.json(+.exit/.stderr), log. Exit 0 hanya bila SEMUA skenario sesuai.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ci="$root/ci"
# shellcheck source=ci/lib.sh
. "$ci/lib.sh"

[ "$#" -eq 2 ] || die "usage: tests/integration/run.sh <image@digest> <out-dir>"
ref="$1" out="$2"
require_digest_ref "$ref"
if [ -e "$out" ] && [ -n "$(ls -A "$out")" ]; then die "direktori output tidak kosong: $out"; fi
mkdir -p "$out"
out="$(cd "$out" && pwd)"
store="${TRUST_STORE:-$ci/trust-store.json}"
[ -f "$store" ] || die "trust store tidak ada: $store"
package="sister-sign"
algorithms=(ed25519 ecdsa-p256-sha256 rsa-pss-sha256)

key_var() {
  case "$1" in
    ed25519) echo DEMO_KEY_ED25519 ;;
    ecdsa-p256-sha256) echo DEMO_KEY_ECDSA_P256 ;;
    rsa-pss-sha256) echo DEMO_KEY_RSA_PSS ;;
  esac
}
for alg in "${algorithms[@]}"; do
  v="$(key_var "$alg")"
  [ -n "${!v:-}" ] || die "$v kosong: secret kunci demo $alg belum diset"
done

echo "== Persiapan: pull image by digest + artefak rilis dari image"
version="$(bash "$ci/resolve-image.sh" "$ref" | sed -n 's/^version=//p')"
meta="$(bash "$ci/extract-binary.sh" "$ref" "$out/.release")"
name="$(sed -n 's/^name=//p' <<<"$meta")"
release_sha="$(sed -n 's/^sha256=//p' <<<"$meta")"
{
  echo "image=$ref"
  echo "digest=${ref##*@}"
  echo "version=$version"
  echo "artifact=$name"
  echo "artifact_sha256=$release_sha"
  echo "trust_store=${store#"$root"/}"
  echo "runner_uid_gid=$(id -u):$(id -g)"
  echo "repo_digests=$(docker image inspect --format '{{join .RepoDigests " "}}' "$ref")"
  echo "commit=${GITHUB_SHA:-local}"
  echo "run=${GITHUB_RUN_ID:-local}"
  echo "time=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} | tee "$out/image.txt"

rows=()
fails=0

# new_case ID NAMA : direktori skenario baru + salinan artefak rilis yang bersih.
new_case() {
  dir="$out/$1-$2"
  mkdir "$dir" # gagal bila sudah ada: tiap skenario wajib di direktori bersih
  mkdir "$dir/dist" "$dir/bundles"
  cp "$out/.release/$name" "$dir/dist/$name"
  export TOOL_RUN_LOG="$dir/commands.txt"
  : >"$TOOL_RUN_LOG"
}

# sign_case ALG : tandatangani artefak skenario dengan kunci demo ALG -> $dir/bundles/
sign_case() {
  local v
  v="$(key_var "$1")"
  bundle="$dir/bundles/$name.$1.bundle.json"
  SIGNING_KEY="${!v}" bash "$ci/sign-artifact.sh" "$ref" "$dir/dist/$name" "$package" "$version" \
    "$bundle" >>"$dir/sign.log" 2>&1
}

# gate ARTEFAK STORE SHA-YANG-DITANDATANGANI : verify -> deploy hanya bila verify exit 0, persis
# urutan pipeline. Mengisi got_exit (exit code asli sister-sign), got_status, got_marker.
gate() {
  local artifact="$1" st="$2" signed_sha="$3" rc=0
  bash "$ci/verify-artifact.sh" "$ref" "$artifact" "$bundle" "$st" "$package" "$version" \
    "$dir/verify/verify.json" >"$dir/verify.log" 2>&1 || rc=$?
  got_exit="$(cat "$dir/verify/verify.json.exit" 2>/dev/null || echo "none (wrapper rc=$rc)")"
  got_status="$(jq -r '.status // "?"' "$dir/verify/verify.json" 2>/dev/null || echo "?")"
  if [ "$rc" -eq 0 ]; then
    bash "$ci/deploy-marker.sh" "$artifact" "$signed_sha" "$dir/bundles" "$dir/verify" "$ref" \
      "$dir/deploy" >"$dir/deploy.log" 2>&1 || echo "deploy gagal (rc=$?)" >>"$dir/deploy.log"
  else
    echo "deploy DILEWATI: verify exit $rc" >"$dir/deploy.log"
  fi
  if [ -f "$dir/deploy/DEPLOYED" ]; then got_marker=ada; else got_marker="tidak ada"; fi
}

# add_row ID SKENARIO DIHARAPKAN HASIL PASS|FAIL [CATATAN] : result.txt + baris tabel.
add_row() {
  local id="$1" what="$2" want="$3" got="$4" res="$5" note="${6:-}"
  [ "$res" = PASS ] || fails=$((fails + 1))
  {
    echo "id=$id"
    echo "scenario=$what"
    echo "expected=$want"
    echo "actual=$got"
    [ -z "$note" ] || echo "note=$note"
    echo "result=$res"
  } >"$dir/result.txt"
  echo "[$res] $id $what: $got${note:+ ($note)}"
  rows+=("| $id | $what | $want | $got | $res | ${note//|/\\|} |")
}

# record ID SKENARIO WANT_EXIT WANT_STATUS WANT_MARKER [CATATAN] : bandingkan hasil gate.
record() {
  local res=PASS
  if [ "$got_exit" != "$3" ] || [ "$got_status" != "$4" ] || [ "$got_marker" != "$5" ]; then
    res=FAIL
  fi
  add_row "$1" "$2" "exit $3, \`$4\`, DEPLOYED $5" \
    "exit $got_exit, \`$got_status\`, DEPLOYED $got_marker" "$res" "${6:-}"
}

# ---- C01: jalur sah x3 algoritma -----------------------------------------------------------------
for alg in "${algorithms[@]}"; do
  echo "== C01 $alg"
  new_case C01 "$alg"
  sign_case "$alg"
  gate "$dir/dist/$name" "$store" "$release_sha"
  record C01 "sign + verify + deploy ($alg)" 0 OK ada "artefak sha256 ${release_sha:0:12}…"
done

# ---- C02: 1 byte diubah setelah sign -------------------------------------------------------------
echo "== C02"
new_case C02 tamper
sign_case ed25519
f="$dir/dist/$name"
size_before="$(wc -c <"$f" | tr -d ' ')"
byte="$(od -An -tu1 -j1 -N1 "$f" | tr -d ' ')"
# shellcheck disable=SC2059 # format oktal sengaja dibangun dari nilai byte
printf "\\$(printf '%03o' $((byte ^ 1)))" | dd of="$f" bs=1 seek=1 conv=notrunc status=none
size_after="$(wc -c <"$f" | tr -d ' ')"
sha_after="$(sha256sum "$f" | cut -d' ' -f1)"
printf 'offset=1\nbefore=%s\nafter=%s\nsize_before=%s\nsize_after=%s\nsha256_before=%s\nsha256_after=%s\n' \
  "$byte" "$((byte ^ 1))" "$size_before" "$size_after" "$release_sha" "$sha_after" >"$dir/tamper.txt"
if [ "$size_before" != "$size_after" ] || [ "$sha_after" = "$release_sha" ]; then
  die "C02: manipulasi tidak sesuai (ukuran berubah atau byte sama)"
fi
gate "$f" "$store" "$release_sha"
record C02 "1 byte artefak diubah setelah sign (ed25519)" 1 ARTIFACT_MISMATCH "tidak ada" \
  "offset 1: $byte -> $((byte ^ 1)), ukuran $size_after B dan nama sama"

# ---- C03: trust store kosong / kunci tidak diizinkan untuk package -------------------------------
echo "== C03 trust store kosong"
new_case C03 empty-store
sign_case ed25519
mkdir "$dir/trust"
printf '{"schema":"minisign-trust/v1","keys":[]}\n' >"$dir/trust/empty.json"
gate "$dir/dist/$name" "$dir/trust/empty.json" "$release_sha"
record C03 "trust store kosong (ed25519)" 1 KEY_NOT_TRUSTED "tidak ada"

echo "== C03 kunci hanya dipercaya untuk package lain"
new_case C03 other-package
sign_case ed25519
mkdir "$dir/trust"
# Kunci yang sama persis, tetapi diizinkan hanya untuk package lain.
jq '.keys |= map(.packages = ["other-package"])' "$store" >"$dir/trust/other-package.json"
gate "$dir/dist/$name" "$dir/trust/other-package.json" "$release_sha"
record C03 "kunci hanya dipercaya untuk package other-package (ed25519)" 1 KEY_NOT_TRUSTED "tidak ada" \
  "kunci, bundle dan artefak sama dengan C01"

# ---- C04: path artefak tidak ada -----------------------------------------------------------------
echo "== C04"
new_case C04 missing-artifact
sign_case ed25519
rm "$dir/dist/$name"
gate "$dir/dist/$name" "$store" "$release_sha"
record C04 "path artefak tidak ada (ed25519)" 2 INPUT_ERROR "tidak ada" "bundle + trust store sah"

# ---- C05: UID/GID runner, tanpa TTY, --network none ----------------------------------------------
echo "== C05"
new_case C05 container-policy
tool_flags
uidgid="$(id -u):$(id -g)"
c05_fail=()
# (a) Konfigurasi container yang dipakai SEMUA skenario, diperiksa lewat docker inspect.
{
  printf 'docker create'
  printf ' %q' "${TOOL_FLAGS[@]}" "$ref" -version
  echo
} >>"$TOOL_RUN_LOG"
cid="$(docker create "${TOOL_FLAGS[@]}" "$ref" -version)"
docker inspect --format 'network={{.HostConfig.NetworkMode}}
user={{.Config.User}}
tty={{.Config.Tty}}
open_stdin={{.Config.OpenStdin}}
attach_stdin={{.Config.AttachStdin}}
readonly_rootfs={{.HostConfig.ReadonlyRootfs}}
cap_drop={{.HostConfig.CapDrop}}
security_opt={{.HostConfig.SecurityOpt}}' "$cid" >"$dir/inspect.txt"
rc=0
docker start -a "$cid" >"$dir/version.out" 2>&1 </dev/null || rc=$?
docker rm "$cid" >/dev/null
grep -qx 'network=none' "$dir/inspect.txt" || c05_fail+=("network bukan none")
grep -qx "user=$uidgid" "$dir/inspect.txt" || c05_fail+=("user bukan $uidgid")
grep -qx 'tty=false' "$dir/inspect.txt" || c05_fail+=("TTY aktif")
grep -qx 'open_stdin=false' "$dir/inspect.txt" || c05_fail+=("stdin terbuka")
if [ "$rc" -ne 0 ] || ! grep -qx "sister-sign $version" "$dir/version.out"; then
  c05_fail+=("-version gagal (rc=$rc)")
fi
# (b) Berkas yang ditulis CLI di output runner dimiliki UID/GID runner (--user benar-benar berlaku).
jq -r '.keys[] | select(.algorithm == "ed25519") | .public_key_pem' "$store" >"$dir/dist/demo.pub.pem"
mkdir "$dir/written"
rc=0
tool_run "$ref" -v "$(host_path "$dir/dist"):/in:ro" -v "$(host_path "$dir/written"):/out" -- \
  trust add -store /out/c05.trust.json -key /in/demo.pub.pem -package c05-check \
  >"$dir/trust-add.out" 2>&1 || rc=$?
owner="$(stat -c '%u:%g' "$dir/written/c05.trust.json" 2>/dev/null || echo none)"
echo "owner=$owner" >>"$dir/inspect.txt"
if [ "$rc" -ne 0 ] || [ "$owner" != "$uidgid" ]; then
  c05_fail+=("trust add rc=$rc, owner $owner")
fi
# (c) Tanpa TTY + stdin ditutup: parameter kurang = error jelas (exit 2), bukan menunggu input.
rc=0
# shellcheck disable=SC2016 # $1/$2 sengaja diekspansi oleh bash -c, bukan di sini
timeout 30 bash -c '. "$1/lib.sh"; tool_run "$2" -- verify' _ "$ci" "$ref" \
  >"$dir/no-args.out" 2>&1 || rc=$?
echo "verify_without_args_exit=$rc" >>"$dir/inspect.txt"
[ "$rc" -eq 2 ] || c05_fail+=("verify tanpa argumen exit $rc (harus 2; 124 = menunggu input)")

c05_got="$(sed -n 's/^\(network\|user\|tty\|open_stdin\)=//p' "$dir/inspect.txt" | paste -sd' ')"
c05_got="network/user/tty/stdin = $c05_got; output milik $owner; verify tanpa argumen exit $rc"
if [ "${#c05_fail[@]}" -eq 0 ]; then c05_res=PASS; else
  c05_res=FAIL
  c05_got="$c05_got; GAGAL: ${c05_fail[*]}"
fi
add_row C05 "image dengan UID/GID runner, tanpa TTY, --network none" \
  "network/user/tty/stdin = none $uidgid false false; output milik $uidgid; verify tanpa argumen exit 2" \
  "$c05_got" "$c05_res" "\`-version\` di container yang sama: $(cat "$dir/version.out")"
unset TOOL_RUN_LOG

# ---- audit + tabel --------------------------------------------------------------------------------
rm -rf "$out/.release"
echo "== Audit privkey"
bash "$ci/audit-no-privkey.sh" "$out" | tee "$out/audit.txt"

{
  echo "# Hasil uji integrasi CI/CD C01-C05"
  echo
  echo "Image: \`$ref\` (sister-sign $version), runner UID/GID $(id -u):$(id -g)," \
    "commit \`${GITHUB_SHA:-local}\`, run \`${GITHUB_RUN_ID:-local}\`."
  echo
  echo "| ID | Skenario | Diharapkan | Hasil | Status | Catatan |"
  echo "|---|---|---|---|---|---|"
  printf '%s\n' "${rows[@]}"
  echo
  echo "$((${#rows[@]} - fails))/${#rows[@]} skenario sesuai harapan. Exit code = exit code asli" \
    "sister-sign (\`verify/verify.json.exit\`); DEPLOYED = \`deploy/DEPLOYED\` di direktori skenario."
} >"$out/results.md"
echo
cat "$out/results.md"
[ "$fails" -eq 0 ] || die "$fails skenario tidak sesuai harapan"
