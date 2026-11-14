#include "util/json_scan.hpp"

#include <cstddef>
#include <cstdint>
#include <set>
#include <string>

namespace sister_sign::util {
namespace {

class Scanner {
 public:
  explicit Scanner(std::string_view s) : s_(s) {}

  Outcome<void> run() {
    skip_ws();
    if (auto r = value(0); !r) return r;
    skip_ws();
    if (pos_ != s_.size()) return fail("data tersisa setelah nilai JSON");
    return {};
  }

 private:
  std::string_view s_;
  std::size_t pos_ = 0;

  Outcome<void> fail(const char* why) const {
    return make_error(Status::FormatError, std::string("JSON tidak valid: ") + why + " (offset " +
                                               std::to_string(pos_) + ")");
  }

  bool eof() const { return pos_ >= s_.size(); }
  char peek() const { return s_[pos_]; }

  void skip_ws() {
    while (!eof() && (peek() == ' ' || peek() == '\t' || peek() == '\n' || peek() == '\r')) ++pos_;
  }

  Outcome<void> value(int depth) {
    if (depth > kJsonMaxDepth) return fail("terlalu dalam");
    if (eof()) return fail("nilai hilang");
    switch (peek()) {
      case '{':
        return object(depth);
      case '[':
        return array(depth);
      case '"': {
        std::string unused;
        return string(unused);
      }
      case 't':
        return literal("true");
      case 'f':
        return literal("false");
      case 'n':
        return literal("null");
      default:
        return number();
    }
  }

  Outcome<void> literal(std::string_view word) {
    if (s_.substr(pos_, word.size()) != word) return fail("literal salah");
    pos_ += word.size();
    return {};
  }

  Outcome<void> number() {
    if (!eof() && peek() == '-') ++pos_;
    if (eof()) return fail("angka tidak lengkap");
    if (peek() == '0') {
      ++pos_;
    } else if (peek() >= '1' && peek() <= '9') {
      while (!eof() && peek() >= '0' && peek() <= '9') ++pos_;
    } else {
      return fail("karakter tak terduga");
    }
    if (!eof() && peek() == '.') {
      ++pos_;
      if (!digits()) return fail("pecahan kosong");
    }
    if (!eof() && (peek() == 'e' || peek() == 'E')) {
      ++pos_;
      if (!eof() && (peek() == '+' || peek() == '-')) ++pos_;
      if (!digits()) return fail("eksponen kosong");
    }
    return {};
  }

  bool digits() {
    std::size_t start = pos_;
    while (!eof() && peek() >= '0' && peek() <= '9') ++pos_;
    return pos_ > start;
  }

  static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  }

  bool read_u4(std::uint32_t& out) {
    if (pos_ + 4 > s_.size()) return false;
    std::uint32_t v = 0;
    for (int i = 0; i < 4; ++i) {
      int h = hex_val(s_[pos_ + i]);
      if (h < 0) return false;
      v = v * 16 + static_cast<std::uint32_t>(h);
    }
    pos_ += 4;
    out = v;
    return true;
  }

  static void append_utf8(std::string& out, std::uint32_t cp) {
    if (cp < 0x80) {
      out += static_cast<char>(cp);
    } else if (cp < 0x800) {
      out += static_cast<char>(0xC0 | (cp >> 6));
      out += static_cast<char>(0x80 | (cp & 0x3F));
    } else if (cp < 0x10000) {
      out += static_cast<char>(0xE0 | (cp >> 12));
      out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
      out += static_cast<char>(0x80 | (cp & 0x3F));
    } else {
      out += static_cast<char>(0xF0 | (cp >> 18));
      out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
      out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
      out += static_cast<char>(0x80 | (cp & 0x3F));
    }
  }

  // Membaca string; `decoded` berisi isi setelah escape didekode (UTF-8).
  Outcome<void> string(std::string& decoded) {
    ++pos_;  // '"'
    while (true) {
      if (eof()) return fail("string tidak ditutup");
      unsigned char c = static_cast<unsigned char>(peek());
      if (c == '"') {
        ++pos_;
        return {};
      }
      if (c < 0x20) return fail("karakter kontrol di dalam string");
      if (c != '\\') {
        decoded += static_cast<char>(c);
        ++pos_;
        continue;
      }
      ++pos_;
      if (eof()) return fail("escape terpotong");
      char e = peek();
      ++pos_;
      switch (e) {
        case '"':
          decoded += '"';
          break;
        case '\\':
          decoded += '\\';
          break;
        case '/':
          decoded += '/';
          break;
        case 'b':
          decoded += '\b';
          break;
        case 'f':
          decoded += '\f';
          break;
        case 'n':
          decoded += '\n';
          break;
        case 'r':
          decoded += '\r';
          break;
        case 't':
          decoded += '\t';
          break;
        case 'u': {
          std::uint32_t cp = 0;
          if (!read_u4(cp)) return fail("escape \\u salah");
          if (cp >= 0xD800 && cp <= 0xDBFF) {
            std::uint32_t lo = 0;
            if (pos_ + 2 <= s_.size() && s_[pos_] == '\\' && s_[pos_ + 1] == 'u') {
              pos_ += 2;
              if (!read_u4(lo) || lo < 0xDC00 || lo > 0xDFFF) return fail("surrogate salah");
              cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
            } else {
              return fail("surrogate tunggal");
            }
          } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
            return fail("surrogate tunggal");
          }
          append_utf8(decoded, cp);
          break;
        }
        default:
          return fail("escape tidak dikenal");
      }
    }
  }

  Outcome<void> array(int depth) {
    ++pos_;  // '['
    skip_ws();
    if (!eof() && peek() == ']') {
      ++pos_;
      return {};
    }
    while (true) {
      skip_ws();
      if (auto r = value(depth + 1); !r) return r;
      skip_ws();
      if (eof()) return fail("array tidak ditutup");
      if (peek() == ',') {
        ++pos_;
        continue;
      }
      if (peek() == ']') {
        ++pos_;
        return {};
      }
      return fail("pemisah array salah");
    }
  }

  Outcome<void> object(int depth) {
    ++pos_;  // '{'
    std::set<std::string> keys;
    skip_ws();
    if (!eof() && peek() == '}') {
      ++pos_;
      return {};
    }
    while (true) {
      skip_ws();
      if (eof() || peek() != '"') return fail("key objek harus string");
      std::string key;
      if (auto r = string(key); !r) return r;
      if (!keys.insert(key).second) {
        return make_error(
            Status::FormatError,
            "JSON tidak valid: key ganda dalam satu objek (offset " + std::to_string(pos_) + ")");
      }
      skip_ws();
      if (eof() || peek() != ':') return fail("':' hilang");
      ++pos_;
      skip_ws();
      if (auto r = value(depth + 1); !r) return r;
      skip_ws();
      if (eof()) return fail("objek tidak ditutup");
      if (peek() == ',') {
        ++pos_;
        continue;
      }
      if (peek() == '}') {
        ++pos_;
        return {};
      }
      return fail("pemisah objek salah");
    }
  }
};

}  // namespace

Outcome<void> check_json_no_duplicate_keys(std::string_view json) { return Scanner(json).run(); }

}  // namespace sister_sign::util
