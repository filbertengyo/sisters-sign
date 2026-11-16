"""Independent implementation of the manifest/bundle format (spec Table 2.1 / 2.3).

Written from the format description, not from sister-sign's code, so a bundle produced here and
accepted by `sister-sign verify` shows the format is reproducible by a third party.
"""

import base64
import binascii
import hashlib
import json
from pathlib import Path

MANIFEST_SCHEMA = "minisign-manifest/v1"
BUNDLE_SCHEMA = "minisign-bundle/v1"


def canonical_manifest(package, version, algorithm, keyid, name, size, sha256):
    """Canonical manifest bytes: fixed field order, no whitespace, ASCII only."""
    m = {
        "schema": MANIFEST_SCHEMA,
        "package": package,
        "version": version,
        "algorithm": algorithm,
        "keyid": keyid,
        "artifact": {"name": name, "size": size, "sha256": sha256},
    }
    return json.dumps(m, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def manifest_for_file(path, package, version, algorithm, keyid):
    data = Path(path).read_bytes()
    return canonical_manifest(
        package, version, algorithm, keyid, Path(path).name, len(data),
        hashlib.sha256(data).hexdigest(),
    )


def write_bundle(path, manifest, signature):
    bundle = {
        "schema": BUNDLE_SCHEMA,
        "manifest_b64": base64.b64encode(manifest).decode("ascii"),
        "signature_b64": base64.b64encode(signature).decode("ascii"),
    }
    Path(path).write_text(json.dumps(bundle, separators=(",", ":")))


def _strict_b64(s):
    raw = base64.b64decode(s, validate=True)
    if base64.b64encode(raw).decode("ascii") != s:
        raise ValueError("non-canonical base64")
    return raw


def read_bundle(path):
    """Return (manifest bytes, signature bytes, parsed manifest) of a bundle sister-sign wrote."""
    bundle = json.loads(Path(path).read_text())
    if set(bundle) != {"schema", "manifest_b64", "signature_b64"}:
        raise ValueError(f"unexpected bundle fields: {sorted(bundle)}")
    if bundle["schema"] != BUNDLE_SCHEMA:
        raise ValueError(f"unexpected bundle schema {bundle['schema']!r}")
    try:
        manifest = _strict_b64(bundle["manifest_b64"])
        signature = _strict_b64(bundle["signature_b64"])
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"bad base64: {e}") from e
    parsed = json.loads(manifest)
    a = parsed["artifact"]
    canonical = canonical_manifest(
        parsed["package"], parsed["version"], parsed["algorithm"], parsed["keyid"],
        a["name"], a["size"], a["sha256"],
    )
    if canonical != manifest:
        raise ValueError("manifest bytes are not canonical")
    return manifest, signature, parsed
