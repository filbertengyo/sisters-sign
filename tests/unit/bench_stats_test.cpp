// Fungsi statistik benchmark: median dan persentil nearest-rank.
#include <doctest/doctest.h>

#include <cstdint>
#include <vector>

#include "stats.hpp"

using sister_sign::bench::mean;
using sister_sign::bench::median;
using sister_sign::bench::nearest_rank;
using sister_sign::bench::percentile;

namespace {
std::vector<std::int64_t> one_to(std::int64_t n) {
  std::vector<std::int64_t> v;
  for (std::int64_t i = n; i >= 1; --i) v.push_back(i);  // sengaja terurut turun
  return v;
}
}  // namespace

TEST_CASE("nearest_rank = ceil(p*n/100), mulai dari 1") {
  CHECK(nearest_rank(1, 95) == 1);
  CHECK(nearest_rank(10, 95) == 10);   // ceil(9.5)
  CHECK(nearest_rank(20, 95) == 19);   // tepat 19
  CHECK(nearest_rank(30, 95) == 29);   // ceil(28.5)
  CHECK(nearest_rank(35, 95) == 34);   // ceil(33.25)
  CHECK(nearest_rank(100, 95) == 95);  // tepat 95
  CHECK(nearest_rank(4, 50) == 2);
  CHECK(nearest_rank(5, 50) == 3);  // ceil(2.5)
  CHECK(nearest_rank(7, 100) == 7);
  CHECK(nearest_rank(7, 1) == 1);
  CHECK(nearest_rank(0, 95) == 0);
  CHECK(nearest_rank(5, 0) == 0);
  CHECK(nearest_rank(5, 101) == 0);
}

TEST_CASE("percentile mengurutkan sendiri dan memakai nearest-rank") {
  CHECK(percentile(one_to(30), 95) == 29);
  CHECK(percentile(one_to(20), 95) == 19);
  CHECK(percentile(one_to(10), 95) == 10);
  CHECK(percentile(one_to(100), 95) == 95);
  CHECK(percentile(one_to(30), 100) == 30);
  CHECK(percentile({42}, 95) == 42);
  CHECK(percentile({5, 1, 4, 2, 3}, 50) == 3);
  CHECK(percentile({7, 7, 7, 1}, 95) == 7);
  CHECK(percentile({}, 95) == 0);
}

TEST_CASE("median: ganjil = tengah, genap = rata-rata dua tengah") {
  CHECK(median({3, 1, 2}) == doctest::Approx(2.0));
  CHECK(median({4, 1, 3, 2}) == doctest::Approx(2.5));
  CHECK(median({10}) == doctest::Approx(10.0));
  CHECK(median(one_to(30)) == doctest::Approx(15.5));
  CHECK(median({}) == doctest::Approx(0.0));
}

TEST_CASE("mean") {
  CHECK(mean({1, 2, 3, 4}) == doctest::Approx(2.5));
  CHECK(mean({}) == doctest::Approx(0.0));
}
