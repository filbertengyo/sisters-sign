#!/usr/bin/env bash
# Runner e2e: menjalankan tiap kasus di direktori kerja bersih, menyimpan bukti, dan membuat tabel.
#
#   run.sh <biner sister-sign> <direktori kasus> <direktori hasil>
#
# Satu kasus = satu berkas `<ID>.sh` di direktori kasus (lihat tests/e2e/README.md). Hasil per
# kasus disimpan di <hasil>/<ID>/ (perintah, masukan, diharapkan, aktual, stdout, stderr), ringkasan
# di <hasil>/results.tsv dan tabel markdown di <hasil>/results.md.
# Exit code: 0 bila semua kasus PASS, 1 bila ada FAIL/ERROR, 2 bila pemakaian salah.
set -u

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <sister-sign binary> <cases dir> <results dir>" >&2
  exit 2
fi
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$(realpath "$1")"
CASES="$(realpath "$2")"
mkdir -p "$3" || exit 2
RESULTS="$(realpath "$3")"
if [ ! -x "$BIN" ] || [ ! -d "$CASES" ] || [ -z "$RESULTS" ] || [ "$RESULTS" = "/" ]; then
  echo "error: biner/direktori tidak valid" >&2
  exit 2
fi

TSV="$RESULTS/results.tsv"
: >"$TSV"
pass=0
fail=0
total=0

# Status aktual dari keluaran perintah terakhir: JSON {"status":"X"}, "X: pesan" di stderr, atau
# "OK: ..." di stdout. Kosong bila tidak ada.
extract_status() {
  local out="$1" err="$2" s=""
  if [ -s "$out" ] && head -c1 "$out" | grep -q '{'; then
    s="$(sed -n 's/.*"status":"\([A-Z_]*\)".*/\1/p' "$out" | head -n1)"
  fi
  if [ -z "$s" ] && [ -s "$err" ]; then
    s="$(sed -n '1s/^\([A-Z_][A-Z_]*\):.*/\1/p' "$err")"
  fi
  if [ -z "$s" ] && [ -s "$out" ]; then
    s="$(sed -n '1s/^\(OK\):.*/\1/p' "$out")"
  fi
  printf '%s' "$s"
}

# Semua berkas .sh di bawah direktori kasus (rekursif), urut nama; ID = nama berkas tanpa .sh.
FORGE_BIN="$(dirname "$BIN")/forge"
while IFS= read -r case_file; do
  id="$(basename "$case_file" .sh)"
  cdir="$RESULTS/$id"
  rm -rf "$cdir"
  mkdir -p "$cdir"
  work="$(mktemp -d)"
  total=$((total + 1))

  # Metadata kasus (tanpa menjalankan run()). Kosongkan dulu supaya nilai kasus sebelumnya tidak
  # bocor ke kasus ini.
  unset DESC EXPECT_EXIT EXPECT_STATUS EXPECT_STDOUT_CONTAINS EXPECT_STDERR_CONTAINS     EXPECT_STDOUT_EMPTY EXPECT_JSON_LINE
  eval "$(
    . "$HERE/lib.sh"
    . "$case_file"
    for v in DESC EXPECT_EXIT EXPECT_STATUS EXPECT_STDOUT_CONTAINS EXPECT_STDERR_CONTAINS \
      EXPECT_STDOUT_EMPTY EXPECT_JSON_LINE; do
      printf '%s=%q\n' "$v" "${!v-}"
    done
  )"

  (
    set +e
    export SIS="$BIN" FORGE="$FORGE_BIN" CASE_OUT="$cdir"
    cd "$work" || exit 98
    . "$HERE/lib.sh"
    . "$case_file"
    if ! declare -F run >/dev/null; then
      echo "kasus tidak punya fungsi run()" >"$cdir/setup_error.txt"
      exit 97
    fi
    run
    exit 0 # exit code run() = perintah terakhir; yang dinilai ada di last.rc
  ) </dev/null >"$cdir/harness.log" 2>&1
  run_rc=$?

  # Bukti masukan: daftar + hash semua berkas kerja; salinan berkas kecil kecuali privkey.
  (cd "$work" && find . -type f | sort | while read -r f; do
    printf '%s  %s  (%s bytes)\n' "$(sha256sum <"$f" | cut -d' ' -f1)" "$f" "$(wc -c <"$f")"
  done) >"$cdir/inputs.txt"
  mkdir -p "$cdir/inputs"
  (cd "$work" && find . -type f ! -name '*.key.pem' -size -65k -print0 |
    while IFS= read -r -d '' f; do
      mkdir -p "$cdir/inputs/$(dirname "$f")"
      cp "$f" "$cdir/inputs/$f"
    done)
  rm -rf "$work"

  expected="exit=${EXPECT_EXIT:-?}"
  [ -n "${EXPECT_STATUS:-}" ] && expected="$expected status=$EXPECT_STATUS"

  verdict="PASS"
  reasons=""
  if [ "$run_rc" -ne 0 ] || [ ! -f "$cdir/last.rc" ]; then
    verdict="ERROR"
    reasons="persiapan/run() gagal (rc=$run_rc)"
    [ -f "$cdir/setup_error.txt" ] && reasons="$reasons: $(cat "$cdir/setup_error.txt")"
    actual="-"
    command="$(tail -n1 "$cdir/commands.txt" 2>/dev/null || true)"
  else
    actual_exit="$(cat "$cdir/last.rc")"
    actual_status="$(extract_status "$cdir/last.out" "$cdir/last.err")"
    actual="exit=$actual_exit"
    [ -n "$actual_status" ] && actual="$actual status=$actual_status"
    command="$(tail -n1 "$cdir/commands.txt")"

    if [ -z "${EXPECT_EXIT:-}" ]; then
      verdict="ERROR"
      reasons="kasus tidak mendefinisikan EXPECT_EXIT"
    else
      [ "$actual_exit" = "$EXPECT_EXIT" ] || {
        verdict="FAIL"
        reasons="$reasons exit $actual_exit != $EXPECT_EXIT;"
      }
      if [ -n "${EXPECT_STATUS:-}" ] && [ "$actual_status" != "$EXPECT_STATUS" ]; then
        verdict="FAIL"
        reasons="$reasons status '$actual_status' != '$EXPECT_STATUS';"
      fi
      if [ -n "${EXPECT_STDOUT_CONTAINS:-}" ] &&
        ! grep -qF -- "$EXPECT_STDOUT_CONTAINS" "$cdir/last.out"; then
        verdict="FAIL"
        reasons="$reasons stdout tidak memuat '$EXPECT_STDOUT_CONTAINS';"
      fi
      if [ -n "${EXPECT_STDERR_CONTAINS:-}" ] &&
        ! grep -qF -- "$EXPECT_STDERR_CONTAINS" "$cdir/last.err"; then
        verdict="FAIL"
        reasons="$reasons stderr tidak memuat '$EXPECT_STDERR_CONTAINS';"
      fi
      if [ -n "${EXPECT_STDOUT_EMPTY:-}" ] && [ -s "$cdir/last.out" ]; then
        verdict="FAIL"
        reasons="$reasons stdout seharusnya kosong;"
      fi
      if [ -n "${EXPECT_JSON_LINE:-}" ]; then
        lines="$(wc -l <"$cdir/last.out")"
        if [ "$lines" -ne 1 ] || ! head -n1 "$cdir/last.out" | grep -q '^{.*}$'; then
          verdict="FAIL"
          reasons="$reasons stdout bukan satu objek JSON satu baris;"
        fi
      fi
    fi
  fi

  # Pemeriksaan tambahan (check_same/check_differs/check_eq di lib.sh): semuanya harus PASS.
  if [ "$verdict" != "ERROR" ] && [ -s "$cdir/checks.txt" ]; then
    checks_total="$(wc -l <"$cdir/checks.txt")"
    checks_ok="$(grep -c '^PASS' "$cdir/checks.txt" || true)"
    expected="$expected checks=$checks_total/$checks_total"
    actual="$actual checks=$checks_ok/$checks_total"
    if [ "$checks_ok" -ne "$checks_total" ]; then
      [ "$verdict" = "PASS" ] && verdict="FAIL"
      reasons="$reasons cek tambahan gagal: $(grep '^FAIL' "$cdir/checks.txt" | tr '\n' ';')"
    fi
  fi

  {
    echo "id: $id"
    echo "desc: ${DESC:-}"
    echo "command: $command"
    echo "expected: $expected"
    [ -n "${EXPECT_STDOUT_CONTAINS:-}" ] && echo "stdout contains: $EXPECT_STDOUT_CONTAINS"
    [ -n "${EXPECT_STDERR_CONTAINS:-}" ] && echo "stderr contains: $EXPECT_STDERR_CONTAINS"
    [ -n "${EXPECT_STDOUT_EMPTY:-}" ] && echo "stdout: kosong"
    [ -n "${EXPECT_JSON_LINE:-}" ] && echo "stdout: satu objek JSON satu baris"
  } >"$cdir/expected.txt"
  {
    echo "actual: $actual"
    echo "verdict: $verdict"
    [ -n "$reasons" ] && echo "reasons:$reasons"
  } >"$cdir/actual.txt"
  cp "$cdir/last.out" "$cdir/stdout.txt" 2>/dev/null || : >"$cdir/stdout.txt"
  cp "$cdir/last.err" "$cdir/stderr.txt" 2>/dev/null || : >"$cdir/stderr.txt"
  rm -f "$cdir/last.out" "$cdir/last.err" "$cdir/last.rc"

  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "${DESC:-}" "$command" "$expected" "$actual" "$verdict" >>"$TSV"
  if [ "$verdict" = "PASS" ]; then
    pass=$((pass + 1))
    printf 'PASS  %s\n' "$id"
  else
    fail=$((fail + 1))
    printf '%s  %s  %s\n' "$verdict" "$id" "$reasons"
  fi
done < <(find "$CASES" -name '*.sh' | sort)

bash "$HERE/make_table.sh" "$TSV" >"$RESULTS/results.md"
printf '\n%d kasus: %d PASS, %d tidak lulus. Tabel: %s\n' "$total" "$pass" "$fail" "$RESULTS/results.md"
[ "$total" -gt 0 ] && [ "$fail" -eq 0 ]
