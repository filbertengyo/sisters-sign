# Helper bersama skrip pipeline. Di-source, jangan dijalankan langsung.
#
# Semua pemanggilan image lewat tool_run: tanpa jaringan, uid/gid pemanggil, rootfs read-only,
# tanpa capability, tanpa TTY, stdin ditutup. Input selalu di-mount :ro; hanya direktori output
# yang bisa ditulis.

export MSYS_NO_PATHCONV=1 # Git Bash di Windows: jangan ubah path di dalam container

die() {
  echo "::error::$*" >&2
  exit 1
}

# Path host untuk `docker -v` (Git Bash di Windows butuh path Windows).
host_path() {
  local p
  p="$(cd "$1" && pwd)"
  if command -v cygpath >/dev/null 2>&1; then cygpath -w "$p"; else printf '%s\n' "$p"; fi
}

# Flag container untuk SEMUA pemanggilan image (juga dipakai uji C05 untuk `docker create` +
# inspect, supaya yang diperiksa sama persis dengan yang dijalankan). Tanpa -t / -i.
# shellcheck disable=SC2034 # dipakai tool_run dan tests/integration/run.sh
tool_flags() {
  TOOL_FLAGS=(--network none --user "$(id -u):$(id -g)" --read-only --cap-drop ALL
    --security-opt no-new-privileges)
}

# tool_run IMAGE [docker-run-args... --] sister-sign-args...
# TOOL_RUN_LOG (opsional): berkas tempat perintah docker run dicatat (bukti uji integrasi).
tool_run() {
  local image="$1"
  shift
  local extra=()
  while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do
    extra+=("$1")
    shift
  done
  [ "${1:-}" = "--" ] && shift
  tool_flags
  if [ -n "${TOOL_RUN_LOG:-}" ]; then
    {
      printf 'docker run --rm'
      printf ' %q' "${TOOL_FLAGS[@]}" "${extra[@]}" "$image" "$@"
      printf ' </dev/null\n'
    } >>"$TOOL_RUN_LOG"
  fi
  docker run --rm "${TOOL_FLAGS[@]}" "${extra[@]}" "$image" "$@" </dev/null
}

# Image wajib dirujuk by digest: <repo>@sha256:<64 hex>.
require_digest_ref() {
  [[ "$1" =~ ^[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}$ ]] ||
    die "image harus dirujuk by digest (<repo>@sha256:<64 hex>), bukan tag: '$1'"
}

# json_step HASIL IMAGE [docker-run-args... --] sister-sign-args... (perintah ber-`-json`)
# stdout -> HASIL, stderr -> HASIL.stderr, exit code ASLI -> HASIL.exit. Return = exit code asli;
# 1 bila exit 0 tetapi stdout bukan satu baris JSON dengan valid=true,status=OK.
json_step() {
  local result="$1"
  shift
  mkdir -p "$(dirname "$result")"
  local rc=0
  tool_run "$@" >"$result" 2>"$result.stderr" || rc=$?
  printf '%s\n' "$rc" >"$result.exit"
  echo "exit=$rc"
  echo "stdout: $(cat "$result")"
  if [ -s "$result.stderr" ]; then echo "stderr: $(cat "$result.stderr")"; fi
  if [ "$rc" -ne 0 ]; then return "$rc"; fi
  if [ "$(wc -l <"$result" | tr -d ' ')" != "1" ] || ! grep -q '^{"valid":true,"status":"OK",' "$result"; then
    echo "::error::exit 0 tetapi JSON tidak menyatakan valid/OK"
    return 1
  fi
}

# Pola header PEM privkey. Disusun dari potongan supaya string ini sendiri tidak pernah muncul
# utuh di log atau di berkas yang diperiksa.
# shellcheck disable=SC2034 # dipakai skrip yang men-source lib.sh
PRIVKEY_PATTERN="-----BEGIN [A-Z0-9 ]*PRIVATE"" KEY-----"
