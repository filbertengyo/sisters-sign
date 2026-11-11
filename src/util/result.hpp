#pragma once
// Kontrak bersama: status, hasil verify, dan tipe error untuk semua komponen.
#include <expected>
#include <string>
#include <string_view>
#include <utility>

namespace sister_sign {

// Urutan enum = prioritas pemeriksaan verify (berhenti di kegagalan pertama).
enum class Status {
  Ok,
  InputError,
  FormatError,
  UnsupportedAlgorithm,
  KeyNotTrusted,
  InvalidSignature,
  MetadataMismatch,
  ArtifactMismatch,
};

// "OK", "INPUT_ERROR", "FORMAT_ERROR", ...
std::string_view to_string(Status s);

// Satu-satunya tempat pemetaan status -> exit code.
// ASUMSI (cek Tabel 2.10 di spek): Ok=0, InputError=2, penolakan lain=1.
int exit_code(Status s);

// Hasil akhir verify; dipakai juga untuk output -json.
struct Result {
  bool valid = false;
  Status status = Status::Ok;
  std::string message;
  std::string algorithm;
  std::string keyid;
  std::string package;
  std::string version;
};

Result ok_result();
Result fail(Status status, std::string message);

// Error untuk fungsi yang bisa gagal; jangan pakai exception melewati batas modul.
struct Error {
  Status status;
  std::string message;
};

template <class T>
using Outcome = std::expected<T, Error>;

inline std::unexpected<Error> make_error(Status status, std::string message) {
  return std::unexpected<Error>(Error{status, std::move(message)});
}

}  // namespace sister_sign
