#!/usr/bin/env bash
# Jalankan benchmark (T29) dua kali dan bandingkan. Build Release.
#
#   bash bench/run.sh [dir-hasil]                 # default bench/results
#   BENCH_IN_DOCKER=1 bash bench/run.sh           # build + jalan di container debian:trixie
#   BENCH_CPU=2 bash bench/run.sh                 # pin program bench ke CPU 2 (taskset); default
#                                                 # di container: 2, di luar container: tanpa pin
#
# Hasil: <dir>/run1/, <dir>/run2/ (raw.csv, summary.csv, sizes.csv, env.txt, summary.md) dan
# <dir>/compare.md. Berkas artefak sementara ditulis ke direktori temp lokal (bukan bind mount),
# supaya waktu hash tidak dipengaruhi filesystem jaringan/VM.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
out="${1:-$root/bench/results}"
extra=("${@:2}")

if [ "${BENCH_IN_DOCKER:-0}" = "1" ]; then
  export MSYS_NO_PATHCONV=1
  src="$root"
  if command -v cygpath >/dev/null 2>&1; then src="$(cygpath -w "$root")"; fi
  rel="${out#"$root"/}"
  [ "$rel" != "$out" ] || {
    echo "dir hasil harus di dalam repo saat BENCH_IN_DOCKER=1" >&2
    exit 2
  }
  # Image: debian:trixie + g++-14 + cmake + libssl-dev (sama dengan CI).
  docker build -q -t sister-sign-bench - >/dev/null <<'EOF'
FROM debian:trixie
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    g++-14 cmake make ninja-build git ca-certificates libssl-dev && rm -rf /var/lib/apt/lists/*
ENV CXX=g++-14
EOF
  exec docker run --rm -e BENCH_CPU="${BENCH_CPU:-2}" -e BENCH_BUILD_DIR=/tmp/build-release -v "$src:/src" -w /src sister-sign-bench bash bench/run.sh "/src/$rel" "${extra[@]}"
fi

build="${BENCH_BUILD_DIR:-$root/build-release}"
gen=()
if command -v ninja >/dev/null 2>&1; then gen=(-G Ninja); fi
cmake -S "$root" -B "$build" "${gen[@]}" -DCMAKE_BUILD_TYPE=Release -DSISTER_SIGN_WERROR=OFF >/dev/null
cmake --build "$build" --target bench -j >"$build/bench-build.log" 2>&1 || {
  tail -30 "$build/bench-build.log" >&2
  exit 1
}
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pin=()
if [ -n "${BENCH_CPU:-}" ] && command -v taskset >/dev/null 2>&1; then pin=(taskset -c "$BENCH_CPU"); fi
for run in run1 run2; do
  rm -rf "${out:?}/$run"
  echo "== $run ${pin[*]}" >&2
  "${pin[@]}" "$build/bench" -out "$out/$run" -work "$work" "${extra[@]}"
done
set +e
bash "$here/compare.sh" "$out/run1/summary.csv" "$out/run2/summary.csv" >"$out/compare.md"
rc=$?
set -e
cat "$out/compare.md"
exit "$rc"
