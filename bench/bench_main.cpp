// Benchmark sister-sign. Metode lengkap: bench/README.md; hasil: docs/benchmark.md.
//
//   bench [-out DIR] [-work DIR] [-iterations N] [-warmup N] [-keygen N] [-sizes B1,B2,...]
//
// Diukur terpisah, dengan std::chrono::steady_clock per operasi:
//   keygen      generate_keypair (N pasangan per profil, + 1 pemanasan)
//   hash        SHA-256 streaming berkas artefak (64 KiB per baca, sama dengan CLI)
//   sign/verify crypto::sign / crypto::verify atas byte manifest kanonik M
//   e2e-sign    `sister-sign sign ...` in-process (baca kunci, hash, M, sign, tulis bundle)
//   e2e-verify  `sister-sign verify ... -json` in-process (Algoritma 2 lengkap)
// Artefak tiap ukuran dibuat SEKALI (isi pseudo-acak deterministik) dan dipakai ketiga profil.
//
// Keluaran di DIR: raw.csv (setiap sampel, termasuk pemanasan), summary.csv, sizes.csv, env.txt,
// summary.md. Kunci yang dibuat hanya kunci benchmark sementara di direktori kerja dan dihapus.
#include <openssl/crypto.h>
#include <openssl/x509.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <tuple>
#include <vector>

#if __has_include(<sys/utsname.h>)
#include <sys/utsname.h>
#define SISTER_SIGN_HAVE_UTSNAME 1
#endif

#include "bundle/bundle.hpp"
#include "cli/cli.hpp"
#include "crypto/keyio.hpp"
#include "manifest/manifest.hpp"
#include "stats.hpp"
#include "trust/trust.hpp"
#include "util/base64.hpp"
#include "util/hash.hpp"
#include "util/hex.hpp"
#include "util/version.hpp"

namespace {

using namespace sister_sign;
namespace fs = std::filesystem;
using Clock = std::chrono::steady_clock;

[[noreturn]] void die(const std::string& message) {
  std::cerr << "bench: " << message << "\n";
  std::exit(1);
}

struct Options {
  fs::path out = "bench/out";
  fs::path work;
  int iterations = 30;
  int warmup = 5;
  int keygen = 21;
  std::vector<std::uint64_t> sizes = {1024, 1024 * 1024, 64 * 1024 * 1024};
};

int parse_int(std::string_view s, std::string_view flag) {
  try {
    std::size_t pos = 0;
    const int v = std::stoi(std::string(s), &pos);
    if (pos != s.size() || v < 0) throw std::invalid_argument("");
    return v;
  } catch (const std::exception&) {
    die("nilai " + std::string(flag) + " tidak valid: " + std::string(s));
  }
}

Options parse_options(int argc, char** argv) {
  Options o;
  for (int i = 1; i < argc; ++i) {
    const std::string_view flag = argv[i];
    if (flag == "-help" || flag == "--help") {
      std::cout << "usage: bench [-out DIR] [-work DIR] [-iterations N] [-warmup N] [-keygen N] "
                   "[-sizes B1,B2,...]\n";
      std::exit(0);
    }
    if (i + 1 >= argc) die("nilai untuk " + std::string(flag) + " hilang");
    const std::string_view value = argv[++i];
    if (flag == "-out") {
      o.out = std::string(value);
    } else if (flag == "-work") {
      o.work = std::string(value);
    } else if (flag == "-iterations") {
      o.iterations = parse_int(value, flag);
    } else if (flag == "-warmup") {
      o.warmup = parse_int(value, flag);
    } else if (flag == "-keygen") {
      o.keygen = parse_int(value, flag);
    } else if (flag == "-sizes") {
      o.sizes.clear();
      std::stringstream ss{std::string(value)};
      for (std::string part; std::getline(ss, part, ',');) {
        o.sizes.push_back(static_cast<std::uint64_t>(std::stoull(part)));
      }
      if (o.sizes.empty()) die("-sizes kosong");
    } else {
      die("flag tidak dikenal: " + std::string(flag));
    }
  }
  if (o.iterations < 30) die("-iterations minimal 30 (spek)");
  if (o.warmup < 5) die("-warmup minimal 5 (spek)");
  if (o.keygen < 5) die("-keygen minimal 5 (spek)");
  return o;
}

// ---- pencatat sampel ----------------------------------------------------------------------------

struct Key {
  std::string op;
  std::string algorithm;  // "-" bila tidak bergantung profil
  std::uint64_t size;     // 0 bila tidak bergantung ukuran artefak
  bool operator<(const Key& o) const {
    return std::tie(op, algorithm, size) < std::tie(o.op, o.algorithm, o.size);
  }
};

class Recorder {
 public:
  explicit Recorder(const fs::path& raw_csv) : raw_(raw_csv) {
    if (!raw_) die("tidak bisa menulis " + raw_csv.string());
    raw_ << "op,algorithm,size_bytes,phase,iteration,ns\n";
  }

  void add(const Key& k, bool warmup, int iteration, std::int64_t ns) {
    raw_ << k.op << "," << k.algorithm << "," << k.size << "," << (warmup ? "warmup" : "measure")
         << "," << iteration << "," << ns << "\n";
    if (!warmup) {
      if (!samples_.contains(k)) order_.push_back(k);
      samples_[k].push_back(ns);
    }
  }

  const std::vector<Key>& order() const { return order_; }
  const std::vector<std::int64_t>& samples(const Key& k) const { return samples_.at(k); }

 private:
  std::ofstream raw_;
  std::vector<Key> order_;
  std::map<Key, std::vector<std::int64_t>> samples_;
};

// Jalankan `f` (harus mengembalikan true) `warmup` kali tanpa dihitung, lalu `n` kali diukur.
template <class F>
void measure(Recorder& rec, const Key& k, int warmup, int n, F&& f) {
  for (int i = 0; i < warmup + n; ++i) {
    const auto t0 = Clock::now();
    const bool ok = f();
    const auto t1 = Clock::now();
    if (!ok) die("operasi gagal: " + k.op + " " + k.algorithm + " " + std::to_string(k.size));
    const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
    rec.add(k, i < warmup, i < warmup ? i + 1 : i - warmup + 1, ns);
  }
}

// ---- artefak dan hash
// ----------------------------------------------------------------------------

// Isi pseudo-acak deterministik (xorshift64*), supaya hasil bisa diulang dan tidak mudah
// dikompresi.
void make_artifact(const fs::path& path, std::uint64_t size) {
  std::ofstream f(path, std::ios::binary | std::ios::trunc);
  if (!f) die("tidak bisa membuat " + path.string());
  std::uint64_t x = 0x9E3779B97F4A7C15ull ^ size;
  std::vector<char> buf(64 * 1024);
  for (std::uint64_t left = size; left > 0;) {
    const std::size_t n = static_cast<std::size_t>(std::min<std::uint64_t>(left, buf.size()));
    for (std::size_t i = 0; i < n; ++i) {
      x ^= x >> 12;
      x ^= x << 25;
      x ^= x >> 27;
      buf[i] = static_cast<char>((x * 0x2545F4914F6CDD1Dull) >> 56);
    }
    f.write(buf.data(), static_cast<std::streamsize>(n));
    left -= n;
  }
  if (!f) die("gagal menulis " + path.string());
}

// Sama dengan jalur hash di CLI sign/verify: baca 64 KiB per langkah, SHA-256 streaming.
std::string sha256_file(const fs::path& path, std::uint64_t& size) {
  std::ifstream in(path, std::ios::binary);
  if (!in) die("tidak bisa membuka " + path.string());
  util::Sha256 hasher;
  Bytes buf(64 * 1024);
  size = 0;
  while (true) {
    in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
    const auto n = static_cast<std::size_t>(in.gcount());
    if (n > 0) {
      if (!hasher.update(ByteView(buf.data(), n))) die("sha256 update gagal");
      size += n;
    }
    if (in.eof()) break;
    if (!in) die("gagal membaca " + path.string());
  }
  auto d = hasher.finish();
  if (!d) die("sha256 finish gagal");
  return util::hex_lower(*d);
}

// ---- ukuran
// ---------------------------------------------------------------------------------------

std::size_t pubkey_der_size(const crypto::PublicKey& k) {
  const int n = i2d_PUBKEY(k.get(), nullptr);
  if (n <= 0) die("i2d_PUBKEY gagal");
  return static_cast<std::size_t>(n);
}

std::size_t privkey_der_size(const crypto::PrivateKey& k) {
  PKCS8_PRIV_KEY_INFO* p8 = EVP_PKEY2PKCS8(k.get());
  if (!p8) die("EVP_PKEY2PKCS8 gagal");
  const int n = i2d_PKCS8_PRIV_KEY_INFO(p8, nullptr);
  PKCS8_PRIV_KEY_INFO_free(p8);
  if (n <= 0) die("i2d_PKCS8_PRIV_KEY_INFO gagal");
  return static_cast<std::size_t>(n);
}

// ---- lingkungan
// -----------------------------------------------------------------------------------

std::string first_line_with(const fs::path& path, std::string_view prefix) {
  std::ifstream f(path);
  for (std::string line; std::getline(f, line);) {
    if (line.starts_with(prefix)) {
      std::string v = line.substr(prefix.size());
      const auto b = v.find_first_not_of(" \t:=\"");
      if (b == std::string::npos) return "";
      v = v.substr(b);
      while (!v.empty() && (v.back() == '"' || v.back() == ' ')) v.pop_back();
      return v;
    }
  }
  return "unknown";
}

std::vector<std::pair<std::string, std::string>> environment(const Options& o) {
  std::vector<std::pair<std::string, std::string>> env;
  const std::time_t now = std::time(nullptr);
  char ts[32];
  std::strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&now));
  env.emplace_back("timestamp_utc", ts);
  env.emplace_back("cpu_model", first_line_with("/proc/cpuinfo", "model name"));
  env.emplace_back("logical_cpus", std::to_string(std::thread::hardware_concurrency()));
  env.emplace_back("mem_total", first_line_with("/proc/meminfo", "MemTotal"));
  env.emplace_back("os", first_line_with("/etc/os-release", "PRETTY_NAME"));
#ifdef SISTER_SIGN_HAVE_UTSNAME
  struct utsname u {};
  if (uname(&u) == 0) {
    env.emplace_back("kernel", std::string(u.sysname) + " " + u.release + " " + u.machine);
  }
#endif
  std::error_code ec;
  env.emplace_back("container", fs::exists("/.dockerenv", ec) ? "docker" : "no");
#if defined(__clang__)
  env.emplace_back("compiler", std::string("clang ") + __clang_version__);
#elif defined(__GNUC__)
  env.emplace_back("compiler", std::string("gcc ") + __VERSION__);
#else
  env.emplace_back("compiler", "unknown");
#endif
#if defined(__OPTIMIZE__)
  env.emplace_back("optimized", "yes");
#else
  env.emplace_back("optimized", "NO (build Release untuk angka yang bermakna)");
#endif
  env.emplace_back("openssl", OpenSSL_version(OPENSSL_VERSION));
  env.emplace_back("sister_sign", std::string(util::version()));
  env.emplace_back("clock", "std::chrono::steady_clock");
  env.emplace_back("iterations", std::to_string(o.iterations));
  env.emplace_back("warmup", std::to_string(o.warmup));
  env.emplace_back("keygen_pairs", std::to_string(o.keygen));
  env.emplace_back("cpu_warmup", "2 s SHA-256 sebelum pengukuran pertama");
  return env;
}

// ---- keluaran
// -------------------------------------------------------------------------------------

std::string fixed(double v, int digits) {
  std::ostringstream s;
  s << std::fixed << std::setprecision(digits) << v;
  return s.str();
}

std::string human_size(std::uint64_t b) {
  if (b >= (1u << 20) && b % (1u << 20) == 0) return std::to_string(b >> 20) + " MiB";
  if (b >= 1024 && b % 1024 == 0) return std::to_string(b >> 10) + " KiB";
  return std::to_string(b) + " B";
}

struct Stat {
  std::size_t n;
  double median, mean;
  std::int64_t p95, min, max;
};

Stat stat_of(const std::vector<std::int64_t>& v) {
  return Stat{v.size(),
              bench::median(v),
              bench::mean(v),
              bench::percentile(v, 95),
              *std::min_element(v.begin(), v.end()),
              *std::max_element(v.begin(), v.end())};
}

// Pemanasan CPU global sebelum pengukuran pertama: frekuensi CPU (turbo/governor) dan penjadwalan
// vCPU di VM butuh waktu untuk stabil; tanpa ini operasi pertama bisa terukur ~2x lebih lambat.
void warm_up_cpu(std::chrono::milliseconds duration) {
  Bytes buf(64 * 1024, 0x5a);
  const auto end = Clock::now() + duration;
  std::uint8_t sink = 0;
  while (Clock::now() < end) {
    auto d = util::sha256(buf);
    if (!d) die("sha256 gagal");
    sink ^= (*d)[0];
    buf[0] = sink;
  }
}

constexpr crypto::Algorithm kAlgorithms[] = {
    crypto::Algorithm::Ed25519, crypto::Algorithm::EcdsaP256, crypto::Algorithm::RsaPss};

}  // namespace

int main(int argc, char** argv) {
  const Options opt = parse_options(argc, argv);
  std::error_code ec;
  fs::create_directories(opt.out, ec);
  if (ec) die("tidak bisa membuat " + opt.out.string());
  const fs::path work = (opt.work.empty() ? fs::temp_directory_path() : opt.work) /
                        ("sister-sign-bench-" + std::to_string(std::time(nullptr)));
  fs::create_directories(work, ec);
  if (ec) die("tidak bisa membuat " + work.string());

  Recorder rec(opt.out / "raw.csv");
  std::cerr << "pemanasan CPU 2 s\n";
  warm_up_cpu(std::chrono::milliseconds(2000));
  std::ostream null_out(nullptr);  // keluaran CLI dibuang
  const cli::Io quiet{null_out, null_out};
  std::ofstream sizes_csv(opt.out / "sizes.csv");
  sizes_csv << "algorithm,item,bytes\n";

  // 1. Keygen. Pasangan pertama dipakai untuk semua pengukuran berikutnya.
  std::map<crypto::Algorithm, crypto::KeyPair> pairs;
  for (auto alg : kAlgorithms) {
    const std::string name(manifest::algorithm_name(alg));
    std::cerr << "keygen " << name << "\n";
    measure(rec, {"keygen", name, 0}, 1, opt.keygen, [&] {
      auto p = crypto::generate_keypair(alg);
      if (!p) return false;
      if (!pairs.contains(alg)) pairs.emplace(alg, std::move(*p));
      return true;
    });
    const auto& kp = pairs.at(alg);
    const fs::path priv = work / (name + ".key.pem");
    const fs::path pub = work / (name + ".pub.pem");
    if (!crypto::write_private_key(priv, kp.priv, true) ||
        !crypto::write_public_key(pub, kp.pub, true)) {
      die("gagal menulis kunci benchmark");
    }
    sizes_csv << name << ",privkey_der_pkcs8," << privkey_der_size(kp.priv) << "\n"
              << name << ",pubkey_der_spki," << pubkey_der_size(kp.pub) << "\n"
              << name << ",privkey_pem," << fs::file_size(priv) << "\n"
              << name << ",pubkey_pem," << fs::file_size(pub) << "\n";
  }
  trust::TrustStore store;
  for (auto alg : kAlgorithms) {
    if (!store.add(pairs.at(alg).pub, "bench")) die("trust add gagal");
  }
  const fs::path store_path = work / "trust.json";
  if (!store.save(store_path)) die("trust save gagal");

  // 2. Artefak (sama untuk ketiga profil) + hash.
  std::map<std::uint64_t, fs::path> artifacts;
  std::map<std::uint64_t, std::string> digests;
  for (auto size : opt.sizes) {
    const fs::path p = work / ("artifact-" + std::to_string(size) + ".bin");
    make_artifact(p, size);
    artifacts[size] = p;
    std::cerr << "hash " << human_size(size) << "\n";
    measure(rec, {"hash", "-", size}, opt.warmup, opt.iterations, [&] {
      std::uint64_t n = 0;
      digests[size] = sha256_file(p, n);
      return n == size;
    });
  }

  // 3. Sign / verify primitif atas M (manifest kanonik artefak ukuran pertama).
  const std::uint64_t m_size = opt.sizes.front();
  for (auto alg : kAlgorithms) {
    const std::string name(manifest::algorithm_name(alg));
    const auto& kp = pairs.at(alg);
    auto id = crypto::keyid(kp.pub);
    if (!id) die("keyid gagal");
    manifest::Manifest m{
        "bench", "1.0.0", name, *id,
        manifest::ArtifactInfo{artifacts[m_size].filename().string(), m_size, digests[m_size]}};
    auto text = manifest::serialize(m);
    if (!text) die("serialize gagal: " + text.error().message);
    const Bytes msg(text->begin(), text->end());
    Bytes sig;
    std::cerr << "sign/verify " << name << "\n";
    measure(rec, {"sign", name, 0}, opt.warmup, opt.iterations, [&] {
      auto s = crypto::sign(kp.priv, msg);
      if (!s) return false;
      sig = std::move(*s);
      return true;
    });
    measure(rec, {"verify", name, 0}, opt.warmup, opt.iterations,
            [&] { return crypto::verify(kp.pub, msg, sig); });
    sizes_csv << name << ",manifest," << msg.size() << "\n"
              << name << ",signature_raw," << sig.size() << "\n"
              << name << ",signature_b64," << util::base64_encode(sig).size() << "\n";
  }

  // 4. End-to-end in-process: CLI sign dan verify -json, per profil x ukuran.
  for (auto alg : kAlgorithms) {
    const std::string name(manifest::algorithm_name(alg));
    const std::string key = (work / (name + ".key.pem")).string();
    for (auto size : opt.sizes) {
      const std::string file = artifacts[size].string();
      const std::string bundle =
          (work / (name + "-" + std::to_string(size) + ".bundle.json")).string();
      const std::string store_s = store_path.string();
      const std::vector<std::string_view> sign_args = {"sign",  "-file",    file,    "-package",
                                                       "bench", "-version", "1.0.0", "-key",
                                                       key,     "-out",     bundle};
      const std::vector<std::string_view> verify_args = {
          "verify", "-file",    file,    "-bundle",  bundle,  "-trust-store",
          store_s,  "-package", "bench", "-version", "1.0.0", "-json"};
      std::cerr << "e2e " << name << " " << human_size(size) << "\n";
      measure(rec, {"e2e-sign", name, size}, opt.warmup, opt.iterations,
              [&] { return cli::run(sign_args, quiet) == 0; });
      measure(rec, {"e2e-verify", name, size}, opt.warmup, opt.iterations,
              [&] { return cli::run(verify_args, quiet) == 0; });
      sizes_csv << name << ",bundle@" << size << "," << fs::file_size(bundle) << "\n";
    }
  }
  sizes_csv.close();

  // 5. Ringkasan.
  std::ofstream sum(opt.out / "summary.csv");
  sum << "op,algorithm,size_bytes,n,median_us,p95_us,min_us,max_us,mean_us\n";
  for (const auto& k : rec.order()) {
    const Stat s = stat_of(rec.samples(k));
    sum << k.op << "," << k.algorithm << "," << k.size << "," << s.n << ","
        << fixed(s.median / 1e3, 3) << "," << fixed(static_cast<double>(s.p95) / 1e3, 3) << ","
        << fixed(static_cast<double>(s.min) / 1e3, 3) << ","
        << fixed(static_cast<double>(s.max) / 1e3, 3) << "," << fixed(s.mean / 1e3, 3) << "\n";
  }
  const auto env = environment(opt);
  std::ofstream envf(opt.out / "env.txt");
  for (const auto& [k, v] : env) envf << k << "=" << v << "\n";

  // summary.md: tabel siap tempel (angka sama dengan summary.csv).
  std::ofstream md(opt.out / "summary.md");
  auto ms = [](double ns) { return fixed(ns / 1e6, 3); };
  auto us = [](double ns) { return fixed(ns / 1e3, 1); };
  md << "Lingkungan: ";
  for (const auto& [k, v] : env) md << "`" << k << "=" << v << "` ";
  md << "\n\n### Keygen (" << opt.keygen << " pasangan per profil)\n\n"
     << "| Profil | median (ms) | P95 (ms) | min (ms) | max (ms) |\n|---|---:|---:|---:|---:|\n";
  for (auto alg : kAlgorithms) {
    const std::string name(manifest::algorithm_name(alg));
    const Stat s = stat_of(rec.samples({"keygen", name, 0}));
    md << "| `" << name << "` | " << ms(s.median) << " | " << ms(static_cast<double>(s.p95))
       << " | " << ms(static_cast<double>(s.min)) << " | " << ms(static_cast<double>(s.max))
       << " |\n";
  }
  md << "\n### Hash SHA-256 artefak (streaming 64 KiB)\n\n"
     << "| Ukuran | median (ms) | P95 (ms) | throughput dari median (MiB/s) "
        "|\n|---|---:|---:|---:|\n";
  for (auto size : opt.sizes) {
    const Stat s = stat_of(rec.samples({"hash", "-", size}));
    const double mibs = (static_cast<double>(size) / (1024.0 * 1024.0)) / (s.median / 1e9);
    md << "| " << human_size(size) << " | " << ms(s.median) << " | "
       << ms(static_cast<double>(s.p95)) << " | " << fixed(mibs, 0) << " |\n";
  }
  md << "\n### Sign / verify atas manifest M\n\n"
     << "| Profil | sign median (µs) | sign P95 (µs) | verify median (µs) | verify P95 (µs) |\n"
     << "|---|---:|---:|---:|---:|\n";
  for (auto alg : kAlgorithms) {
    const std::string name(manifest::algorithm_name(alg));
    const Stat s = stat_of(rec.samples({"sign", name, 0}));
    const Stat v = stat_of(rec.samples({"verify", name, 0}));
    md << "| `" << name << "` | " << us(s.median) << " | " << us(static_cast<double>(s.p95))
       << " | " << us(v.median) << " | " << us(static_cast<double>(v.p95)) << " |\n";
  }
  md << "\n### End-to-end in-process (`sign` dan `verify -json`)\n\n"
     << "| Profil | Artefak | sign median (ms) | sign P95 (ms) | verify median (ms) | verify P95 "
        "(ms) |\n|---|---|---:|---:|---:|---:|\n";
  for (auto alg : kAlgorithms) {
    const std::string name(manifest::algorithm_name(alg));
    for (auto size : opt.sizes) {
      const Stat s = stat_of(rec.samples({"e2e-sign", name, size}));
      const Stat v = stat_of(rec.samples({"e2e-verify", name, size}));
      md << "| `" << name << "` | " << human_size(size) << " | " << ms(s.median) << " | "
         << ms(static_cast<double>(s.p95)) << " | " << ms(v.median) << " | "
         << ms(static_cast<double>(v.p95)) << " |\n";
    }
  }
  md << "\nUkuran (byte): lihat `sizes.csv`.\n";

  fs::remove_all(work, ec);
  std::cerr << "hasil: " << opt.out.string() << "\n";
  return 0;
}
