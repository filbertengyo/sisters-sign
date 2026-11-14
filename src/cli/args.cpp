#include "cli/args.hpp"

#include <algorithm>

namespace sister_sign::cli {
namespace {

Error input_error(std::string msg) { return Error{Status::InputError, std::move(msg)}; }

const Flag* find_flag(std::span<const Flag> flags, std::string_view name) {
  for (const auto& f : flags) {
    if (f.name == name) return &f;
  }
  return nullptr;
}

// "-name", "--name", atau "-name=value". false bila bukan bentuk flag.
bool split_flag(std::string_view arg, std::string_view& name, std::string_view& value,
                bool& has_value) {
  if (arg.size() < 2 || arg[0] != '-') return false;
  arg.remove_prefix(arg[1] == '-' ? 2 : 1);
  if (arg.empty()) return false;
  auto eq = arg.find('=');
  has_value = eq != std::string_view::npos;
  name = arg.substr(0, eq);
  value = has_value ? arg.substr(eq + 1) : std::string_view{};
  return !name.empty();
}

}  // namespace

std::string_view Parsed::value(std::string_view name) const {
  auto it = values_.find(std::string(name));
  return it == values_.end() ? std::string_view{} : std::string_view(it->second);
}

Outcome<Parsed> parse_flags(std::span<const std::string_view> args, std::span<const Flag> flags) {
  Parsed out;
  for (std::size_t i = 0; i < args.size(); ++i) {
    std::string_view name, inline_value;
    bool has_inline = false;
    if (!split_flag(args[i], name, inline_value, has_inline)) {
      return std::unexpected(input_error("argumen tidak dikenal: '" + std::string(args[i]) + "'"));
    }
    if (name == "help" && !has_inline) {
      out.help_ = true;
      return out;
    }
    const Flag* flag = find_flag(flags, name);
    if (flag == nullptr) {
      return std::unexpected(input_error("flag tidak dikenal: -" + std::string(name)));
    }
    if (out.present_.contains(std::string(name))) {
      return std::unexpected(
          input_error("flag -" + std::string(name) + " diberikan lebih dari sekali"));
    }

    if (!flag->takes_value) {
      if (has_inline) {
        return std::unexpected(input_error("flag -" + std::string(name) + " tidak memakai nilai"));
      }
      out.present_.insert(std::string(name));
      continue;
    }

    std::string_view value;
    if (has_inline) {
      value = inline_value;
    } else {
      if (i + 1 >= args.size()) {
        return std::unexpected(input_error("flag -" + std::string(name) + " butuh nilai"));
      }
      value = args[++i];
      std::string_view n2, v2;
      bool h2 = false;
      if (split_flag(value, n2, v2, h2) && find_flag(flags, n2) != nullptr) {
        return std::unexpected(input_error("flag -" + std::string(name) + " butuh nilai"));
      }
    }
    if (value.empty()) {
      return std::unexpected(input_error("flag -" + std::string(name) + " tidak boleh kosong"));
    }
    out.present_.insert(std::string(name));
    out.values_.emplace(std::string(name), std::string(value));
  }

  for (const auto& f : flags) {
    if (f.required && !out.present_.contains(std::string(f.name))) {
      return std::unexpected(input_error("flag wajib hilang: -" + std::string(f.name)));
    }
  }
  return out;
}

std::string usage_text(std::string_view command, std::string_view summary,
                       std::span<const Flag> flags) {
  std::string out = "usage: sister-sign " + std::string(command);
  for (const auto& f : flags) {
    std::string part = "-" + std::string(f.name);
    if (f.takes_value) part += " <" + std::string(f.name) + ">";
    out += f.required ? " " + part : " [" + part + "]";
  }
  out += "\n";
  out += std::string(summary) + "\n";
  for (const auto& f : flags) {
    out += "  -" + std::string(f.name) + "  " + std::string(f.help) +
           (f.required ? "" : " (opsional)") + "\n";
  }
  return out;
}

}  // namespace sister_sign::cli
