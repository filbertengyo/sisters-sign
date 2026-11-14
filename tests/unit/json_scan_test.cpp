#include "util/json_scan.hpp"

#include <doctest/doctest.h>

#include <string>

using sister_sign::Status;
using sister_sign::util::check_json_no_duplicate_keys;

namespace {
void accepts(const std::string& j) {
  INFO(j);
  CHECK(check_json_no_duplicate_keys(j).has_value());
}
void rejects(const std::string& j) {
  INFO(j);
  auto r = check_json_no_duplicate_keys(j);
  REQUIRE_FALSE(r.has_value());
  CHECK(r.error().status == Status::FormatError);
}
}  // namespace

TEST_CASE("json_scan: JSON valid diterima") {
  accepts(R"({})");
  accepts(R"([])");
  accepts(R"(  {"a":1,"b":[1,2,{"c":null}],"d":"x","e":true,"f":-0.5e+3}  )");
  accepts(R"({"a":{"x":1},"b":{"x":2}})");  // key sama di objek berbeda boleh
  accepts(R"("teks")");
}

TEST_CASE("json_scan: key ganda ditolak") {
  rejects(R"({"a":1,"a":2})");
  rejects(R"({"a":1,"b":2,"a":3})");
  rejects(R"({"x":{"a":1,"a":2}})");
  rejects(R"([{"a":1,"a":2}])");
}

TEST_CASE("json_scan: key ganda lewat escape dianggap sama") {
  rejects(R"({"a":1,"a":2})");
  rejects(R"({"a\nb":1,"a\u000ab":2})");
  rejects(R"({"😀":1,"😀":2})");
}

TEST_CASE("json_scan: sintaks rusak ditolak") {
  rejects("");
  rejects("{");
  rejects(R"({"a":})");
  rejects(R"({"a":1,})");
  rejects(R"({"a" 1})");
  rejects(R"({a:1})");
  rejects(R"([1,])");
  rejects(R"({"a":1} x)");
  rejects(R"({"a":01})");
  rejects(R"({"a":1.})");
  rejects(R"({"a":1e})");
  rejects(R"({"a":+1})");
  rejects(R"({"a":tru})");
  rejects(R"("tak ditutup)");
  rejects(R"("\x")");
  rejects(R"("\u12")");
  rejects(R"("\ud800")");
  rejects(R"("\udc00")");
  rejects(std::string("\"a\nb\""));  // karakter kontrol mentah
}

TEST_CASE("json_scan: kedalaman dibatasi") {
  std::string ok(sister_sign::util::kJsonMaxDepth, '[');
  ok += std::string(sister_sign::util::kJsonMaxDepth, ']');
  accepts(ok);
  std::string deep(sister_sign::util::kJsonMaxDepth + 2, '[');
  deep += std::string(sister_sign::util::kJsonMaxDepth + 2, ']');
  rejects(deep);
}
