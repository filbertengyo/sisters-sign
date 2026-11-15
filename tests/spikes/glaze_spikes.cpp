#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <glaze/glaze.hpp>
#include <optional>

#include "doctest.h"

struct TestStructA {
  int a = 0;
  bool operator==(const TestStructA&) const = default;
};

struct TestStructB {
  std::optional<int> a = std::nullopt;
  bool operator==(const TestStructB&) const = default;
};

struct TestStructC {
  float a = 0;
  bool operator==(const TestStructC&) const = default;
};

template <typename T, glz::opts O>
bool ExpectValue(std::string payload, T expected) {
  T result;
  auto error = glz::read<O>(result, payload);
  if (error) {
    MESSAGE(glz::format_error(error, payload));
    return false;
  } else {
    return result == expected;
  }
}

template <typename T>
bool ExpectValue(std::string payload, T expected) {
  T result;
  auto error = glz::read_json(result, payload);
  if (error) {
    MESSAGE(glz::format_error(error, payload));
    return false;
  } else {
    return result == expected;
  }
}

template <typename T, glz::opts O>
bool ExpectError(std::string payload, glz::error_code code) {
  T result;
  auto error = glz::read<O>(result, payload);
  MESSAGE(glz::format_error(error, payload));
  return error.ec == code;
}

template <typename T>
bool ExpectError(std::string payload, glz::error_code code) {
  T result;
  auto error = glz::read_json(result, payload);
  MESSAGE(glz::format_error(error, payload));
  return error.ec == code;
}

TEST_CASE("check glaze behaviour") {
  constexpr glz::opts RejectMissingKeys{
      .error_on_missing_keys = true,
  };

  constexpr glz::opts AllowUnknownKeys{
      .error_on_unknown_keys = false,
  };

  SUBCASE("duplicate keys") {
    std::string payload = R"({"a":1,"a":2})";
    TestStructA expected = {2};
    CHECK(ExpectValue(payload, expected));
  }
  SUBCASE("extra field") {
    std::string payload = R"({"a":1,"a":2,"b":3})";
    glz::error_code expected = glz::error_code::unknown_key;
    CHECK(ExpectError<TestStructA>(payload, expected));
  }
  SUBCASE("extra field without error_on_unknown_keys") {
    std::string payload = R"({"a":1,"a":2,"b":3})";
    TestStructA expected = {2};
    CHECK(ExpectValue<TestStructA, AllowUnknownKeys>(payload, expected));
  }
  SUBCASE("null value on non-optional field") {
    std::string payload = R"({"a":1,"a":null})";
    glz::error_code expected = glz::error_code::parse_number_failure;
    CHECK(ExpectError<TestStructA>(payload, expected));
  }
  SUBCASE("null value on optional field") {
    std::string payload = R"({"a":1,"a":null})";
    TestStructB expected = {std::nullopt};
    CHECK(ExpectValue(payload, expected));
  }
  SUBCASE("mismatched compatible value type") {
    std::string payload = R"({"a":1,"a":false})";
    glz::error_code expected = glz::error_code::parse_number_failure;
    CHECK(ExpectError<TestStructA>(payload, expected));
  }
  SUBCASE("mismatched incompatible value type") {
    std::string payload = R"({"a":1,"a":"string"})";
    glz::error_code expected = glz::error_code::parse_number_failure;
    CHECK(ExpectError<TestStructA>(payload, expected));
  }
  SUBCASE("missing non-optional field") {
    std::string payload = R"({})";
    TestStructA expected = {0};
    CHECK(ExpectValue(payload, expected));
  }
  SUBCASE("missing non-optional field with error_on_missing_keys") {
    std::string payload = R"({})";
    glz::error_code expected = glz::error_code::missing_key;
    CHECK(ExpectError<TestStructA, RejectMissingKeys>(payload, expected));
  }
  SUBCASE("missing optional field") {
    std::string payload = R"({})";
    TestStructB expected = {std::nullopt};
    CHECK(ExpectValue(payload, expected));
  }
  SUBCASE("reversed fields") {
    std::string payload = R"({"a":2,"a":1})";
    TestStructA expected = {1};
    CHECK(ExpectValue(payload, expected));
  }
  SUBCASE("int format on float field") {
    std::string payload = R"({"a":1,"a":2})";
    TestStructC expected = {2.0};
    CHECK(ExpectValue(payload, expected));
  }
  SUBCASE("float format on int field") {
    std::string payload = R"({"a":1.0,"a":2.0})";
    glz::error_code expected = glz::error_code::parse_number_failure;
    CHECK(ExpectError<TestStructA>(payload, expected));
  }
}
