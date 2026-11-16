#include <fstream>

int main() {
  // create old vulnerable artifact
  std::ofstream old_artifact("old_artifact");
  old_artifact << "vulnerable";
  old_artifact.close();

  // create new patched artifact
  std::ofstream new_artifact("new_artifact");
  new_artifact << "patched";
  new_artifact.close();

  int code = 0;

  // create key
  code = std::system("./sister-sign keygen --algorithm ed25519 --out rollback.demo -force");
  if (code) goto end;

  // add key to trust store
  code = std::system(
      "./sister-sign trust add --key rollback.demo.pub.pem --package rollback.demo --store "
      "rollback.demo.trust.json");
  if (code) goto end;

  // sign old vulnerable artifact
  code = std::system(
      "./sister-sign sign --file old_artifact --package rollback.demo --version 1.0 --key "
      "rollback.demo.key.pem --out rollback.demo.v1.bundle.json");
  if (code) goto end;

  // verify old vulnerable artifact
  code = std::system(
      "./sister-sign verify --file old_artifact --bundle rollback.demo.v1.bundle.json "
      "--trust-store rollback.demo.trust.json --package rollback.demo --version 1.0");
  if (code) goto end;

  // sign new patched artifact
  code = std::system(
      "./sister-sign sign --file new_artifact --package rollback.demo --version 1.1 --key "
      "rollback.demo.key.pem --out rollback.demo.v2.bundle.json");
  if (code) goto end;

  // verify new patched artifact
  code = std::system(
      "./sister-sign verify --file new_artifact --bundle rollback.demo.v2.bundle.json "
      "--trust-store rollback.demo.trust.json --package rollback.demo --version 1.1");
  if (code) goto end;

  // verify old vulnerable artifact
  code = std::system(
      "./sister-sign verify --file old_artifact --bundle rollback.demo.v1.bundle.json "
      "--trust-store rollback.demo.trust.json --package rollback.demo --version 1.0");
  if (code) goto end;

end:
  return code;
}
