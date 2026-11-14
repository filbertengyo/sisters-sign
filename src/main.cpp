#include <iostream>
#include <string_view>
#include <vector>

#include "cli/cli.hpp"

int main(int argc, char** argv) {
  std::vector<std::string_view> args(argv + 1, argv + argc);
  return sister_sign::cli::run(args, sister_sign::cli::Io{std::cout, std::cerr});
}
