#pragma once
// Statistik ringkas untuk benchmark. Header-only supaya bisa diuji di unit_tests tanpa
// menautkan program benchmark.
//
// Definisi yang dipakai di docs/benchmark.md:
//   median : n ganjil -> elemen tengah; n genap -> rata-rata dua elemen tengah.
//   Pp     : nearest-rank, rank = ceil(p/100 * n) dihitung dengan bilangan bulat, posisi mulai
//            dari 1 pada data terurut naik (P95 dari 30 sampel = sampel ke-29).
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace sister_sign::bench {

// Rank nearest-rank (1-based) untuk persentil `p` (1..100) dari `n` sampel; 0 bila tidak
// terdefinisi.
constexpr std::size_t nearest_rank(std::size_t n, unsigned p) {
  if (n == 0 || p == 0 || p > 100) return 0;
  return (static_cast<std::size_t>(p) * n + 99) / 100;  // ceil(p * n / 100)
}

// Persentil nearest-rank; 0 untuk data kosong atau p di luar 1..100.
inline std::int64_t percentile(std::vector<std::int64_t> v, unsigned p) {
  const std::size_t rank = nearest_rank(v.size(), p);
  if (rank == 0) return 0;
  std::sort(v.begin(), v.end());
  return v[rank - 1];
}

inline double median(std::vector<std::int64_t> v) {
  if (v.empty()) return 0.0;
  std::sort(v.begin(), v.end());
  const std::size_t n = v.size();
  if (n % 2 == 1) return static_cast<double>(v[n / 2]);
  return (static_cast<double>(v[n / 2 - 1]) + static_cast<double>(v[n / 2])) / 2.0;
}

inline double mean(const std::vector<std::int64_t>& v) {
  if (v.empty()) return 0.0;
  long double sum = 0;
  for (auto x : v) sum += static_cast<long double>(x);
  return static_cast<double>(sum / static_cast<long double>(v.size()));
}

}  // namespace sister_sign::bench
