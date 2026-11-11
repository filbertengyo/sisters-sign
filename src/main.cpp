#include <iostream>
#include <string_view>

#include "util/version.hpp"

int main(int argc, char** argv) {
  if (argc < 2) {
    std::cerr << "usage: sister-sign <keygen|sign|verify|trust> [options]\n";
    return 2;
  }
  const std::string_view cmd = argv[1];
  if (cmd == "-help" || cmd == "--help") {
    std::cout << "sister-sign - sign and verify software artifacts\n"
                 "usage: sister-sign <keygen|sign|verify|trust> [options]\n"
                 "global flags: -help, -version\n";
    return 0;
  }
  if (cmd == "-version" || cmd == "--version") {
    std::cout << "sister-sign " << sister_sign::util::version() << "\n";
    return 0;
  }
  std::cerr << "unknown command: " << cmd << "\n";
  return 2;
}
