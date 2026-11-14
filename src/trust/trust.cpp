#include "trust/trust.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <glaze/glaze.hpp>
#include <set>

#include "manifest/manifest.hpp"
#include "util/json_scan.hpp"

namespace sister_sign::trust {
namespace {

struct RawEntry {
  std::string keyid;
  std::string algorithm;
  std::string public_key_pem;
  std::vector<std::string> packages;
};

struct RawStore {
  std::string schema;
  std::vector<RawEntry> keys;
};

Error bad(std::string msg) { return Error{Status::FormatError, "trust store: " + std::move(msg)}; }

Error io_error(const std::string& what, int err) {
  return Error{Status::InputError, what + ": " + std::strerror(err)};
}

Outcome<void> validate_packages(const std::vector<std::string>& packages) {
  if (packages.empty()) return std::unexpected(bad("packages kosong"));
  std::set<std::string> seen;
  for (const auto& p : packages) {
    // valid_package menolak wildcard dan karakter di luar pola.
    if (!manifest::valid_package(p)) return std::unexpected(bad("package tidak valid"));
    if (!seen.insert(p).second) return std::unexpected(bad("package ganda"));
  }
  return {};
}

}  // namespace

Outcome<TrustStore> TrustStore::parse(std::string_view json) {
  if (json.size() > kMaxStoreBytes) return std::unexpected(bad("melebihi batas ukuran"));
  if (json.starts_with("\xEF\xBB\xBF")) return std::unexpected(bad("BOM tidak diperbolehkan"));
  if (auto r = util::check_json_no_duplicate_keys(json); !r) return std::unexpected(r.error());

  RawStore raw;
  constexpr glz::opts kOpts{.error_on_unknown_keys = true, .error_on_missing_keys = true};
  if (auto ec = glz::read<kOpts>(raw, json)) {
    return std::unexpected(bad("struktur/tipe tidak sesuai skema"));
  }
  if (raw.schema != kSchema) return std::unexpected(bad("schema salah"));

  TrustStore store;
  std::set<std::string> keyids;
  for (auto& e : raw.keys) {
    if (!manifest::valid_hex64(e.keyid)) return std::unexpected(bad("keyid tidak valid"));
    if (!keyids.insert(e.keyid).second) return std::unexpected(bad("keyid ganda"));
    if (auto r = validate_packages(e.packages); !r) return std::unexpected(r.error());
    crypto::Algorithm alg;
    if (!manifest::parse_algorithm_name(e.algorithm, alg)) {
      return std::unexpected(bad("algoritma tidak dikenal"));
    }
    auto key = crypto::parse_public_key_pem(e.public_key_pem);
    if (!key) return std::unexpected(bad("public_key_pem tidak sah atau di luar profil"));
    if (key->algorithm() != alg) return std::unexpected(bad("algoritma tidak cocok dengan kunci"));
    auto id = crypto::keyid(*key);
    if (!id) return std::unexpected(id.error());
    if (*id != e.keyid) return std::unexpected(bad("fingerprint tidak cocok dengan kunci"));

    store.entries_.push_back(Entry{std::move(e.keyid), alg, std::move(e.public_key_pem),
                                   std::move(e.packages), std::move(*key)});
  }
  return store;
}

Outcome<TrustStore> TrustStore::load(const std::filesystem::path& path) {
  std::ifstream f(path, std::ios::binary);
  if (!f) return make_error(Status::InputError, "trust store tidak bisa dibaca");
  std::string data;
  char buf[4096];
  while (f.read(buf, sizeof buf) || f.gcount() > 0) {
    data.append(buf, static_cast<std::size_t>(f.gcount()));
    if (data.size() > kMaxStoreBytes) return std::unexpected(bad("melebihi batas ukuran"));
  }
  if (f.bad()) return make_error(Status::InputError, "trust store gagal dibaca");
  return parse(data);
}

Outcome<TrustStore> TrustStore::load_or_empty(const std::filesystem::path& path) {
  std::error_code ec;
  if (!std::filesystem::exists(path, ec) && !ec) return TrustStore{};
  return load(path);
}

Outcome<const crypto::PublicKey*> TrustStore::lookup(std::string_view keyid,
                                                     std::string_view package,
                                                     crypto::Algorithm algorithm) const {
  for (const auto& e : entries_) {
    if (e.keyid != keyid) continue;
    if (e.algorithm != algorithm) break;
    if (std::find(e.packages.begin(), e.packages.end(), package) == e.packages.end()) break;
    return &e.key;
  }
  return make_error(Status::KeyNotTrusted, "kunci tidak dipercaya untuk package ini");
}

Outcome<void> TrustStore::add(const crypto::PublicKey& key, std::string_view package) {
  if (!manifest::valid_package(package)) {
    return make_error(Status::InputError, "package tidak sesuai pola");
  }
  auto id = crypto::keyid(key);
  if (!id) return std::unexpected(id.error());

  for (auto& e : entries_) {
    if (e.keyid != *id) continue;
    if (std::find(e.packages.begin(), e.packages.end(), package) == e.packages.end()) {
      e.packages.emplace_back(package);
    }
    return {};
  }

  auto pem = crypto::public_key_to_pem(key);
  if (!pem) return std::unexpected(pem.error());
  // Salin kunci lewat PEM agar store memiliki salinannya sendiri.
  auto copy = crypto::parse_public_key_pem(*pem);
  if (!copy) return std::unexpected(copy.error());
  entries_.push_back(Entry{*id, key.algorithm(), std::move(*pem),
                           std::vector<std::string>{std::string(package)}, std::move(*copy)});
  return {};
}

Outcome<void> TrustStore::remove(std::string_view keyid) {
  auto it = std::find_if(entries_.begin(), entries_.end(),
                         [&](const Entry& e) { return e.keyid == keyid; });
  if (it == entries_.end()) return make_error(Status::InputError, "keyid tidak ada di trust store");
  entries_.erase(it);
  return {};
}

Outcome<std::string> TrustStore::to_json() const {
  RawStore raw;
  raw.schema = std::string(kSchema);
  for (const auto& e : entries_) {
    RawEntry r{e.keyid, std::string(manifest::algorithm_name(e.algorithm)), e.public_key_pem,
               e.packages};
    std::sort(r.packages.begin(), r.packages.end());
    raw.keys.push_back(std::move(r));
  }
  std::sort(raw.keys.begin(), raw.keys.end(),
            [](const RawEntry& a, const RawEntry& b) { return a.keyid < b.keyid; });

  std::string out;
  constexpr glz::opts kOpts{.prettify = true};
  if (auto ec = glz::write<kOpts>(raw, out)) {
    return make_error(Status::FormatError, "trust store: gagal serialisasi");
  }
  out += '\n';
  return out;
}

Outcome<void> TrustStore::save(const std::filesystem::path& path) const {
  auto json = to_json();
  if (!json) return std::unexpected(json.error());

  std::filesystem::path dir = path.parent_path();
  if (dir.empty()) dir = ".";
  const std::filesystem::path tmp =
      dir / ("." + path.filename().string() + ".tmp-" + std::to_string(::getpid()));

  const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
  if (fd < 0) return std::unexpected(io_error("tidak bisa membuat berkas sementara", errno));

  int err = 0;
  const char* p = json->data();
  std::size_t left = json->size();
  while (left > 0) {
    ssize_t n = ::write(fd, p, left);
    if (n < 0) {
      if (errno == EINTR) continue;
      err = errno;
      break;
    }
    p += n;
    left -= static_cast<std::size_t>(n);
  }
  if (err == 0 && ::fsync(fd) != 0) err = errno;
  if (::close(fd) != 0 && err == 0) err = errno;
  if (err == 0 && ::rename(tmp.c_str(), path.c_str()) != 0) err = errno;
  if (err != 0) {
    ::unlink(tmp.c_str());
    return std::unexpected(io_error("gagal menulis trust store", err));
  }

  // fsync direktori agar rename tahan crash; kegagalannya tidak membatalkan hasil yang sudah ada.
  const int dfd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (dfd >= 0) {
    (void)::fsync(dfd);
    ::close(dfd);
  }
  return {};
}

}  // namespace sister_sign::trust
