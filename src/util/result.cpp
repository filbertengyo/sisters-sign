#include "util/result.hpp"

namespace sister_sign {

std::string_view to_string(Status s) {
  switch (s) {
    case Status::Ok:
      return "OK";
    case Status::InputError:
      return "INPUT_ERROR";
    case Status::FormatError:
      return "FORMAT_ERROR";
    case Status::UnsupportedAlgorithm:
      return "UNSUPPORTED_ALGORITHM";
    case Status::KeyNotTrusted:
      return "KEY_NOT_TRUSTED";
    case Status::InvalidSignature:
      return "INVALID_SIGNATURE";
    case Status::MetadataMismatch:
      return "METADATA_MISMATCH";
    case Status::ArtifactMismatch:
      return "ARTIFACT_MISMATCH";
  }
  return "UNKNOWN";
}

int exit_code(Status s) {
  switch (s) {
    case Status::Ok:
      return 0;
    case Status::InputError:
      return 2;
    case Status::FormatError:
    case Status::UnsupportedAlgorithm:
    case Status::KeyNotTrusted:
    case Status::InvalidSignature:
    case Status::MetadataMismatch:
    case Status::ArtifactMismatch:
      return 1;
  }
  return 2;
}

Result ok_result() {
  Result r;
  r.valid = true;
  r.status = Status::Ok;
  r.message = "OK";
  return r;
}

Result fail(Status status, std::string message) {
  Result r;
  r.valid = false;
  r.status = status;
  r.message = std::move(message);
  return r;
}

}  // namespace sister_sign
