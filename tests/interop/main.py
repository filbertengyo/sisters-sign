"""T28 interop: sister-sign <-> an independent implementation (Python `cryptography`, openssl CLI).

usage: python -m interop.main <path/to/sister-sign> [out-dir]     (run from tests/)

For each of the 3 algorithms, both directions:
  external -> sister-sign : keys and a bundle made entirely in Python (manifest, signature, bundle)
                            are accepted by `trust add`, `sign` and `verify`.
  sister-sign -> external : keys from `keygen` and a bundle from `sign` are read and verified by
                            Python `cryptography` (and the openssl CLI when it is installed).
Extra: ECDSA DER <-> r||s conversion and rejection of a raw DER signature; RSA-PSS salt pinning.
Writes <out-dir>/results.md; exit status 1 when any case fails.
"""

import json
import shutil
import sys
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from . import ecdsa_p256_sha256, ed25519, rsa_pss_sha256
from . import generate_bundle as gb
from .common import (
    OPENSSL, CaseFailed, Results, Tool, expect, keyid_of, openssl_verify, parse_field,
    private_pem, public_pem,
)

ALGORITHMS = [rsa_pss_sha256, ecdsa_p256_sha256, ed25519]
PACKAGE = "interop"
VERSION = "1.0.0"
ARTIFACT = "artifact.bin"
TO_US = "external -> sister-sign"
FROM_US = "sister-sign -> external"


def verify_json(tool, bundle, store="trust.json"):
    rc, out, err = tool.run("verify", "-file", ARTIFACT, "-bundle", bundle, "-trust-store", store,
                            "-package", PACKAGE, "-version", VERSION, "-json")
    try:
        result = json.loads(out)
    except json.JSONDecodeError:
        raise CaseFailed(f"verify exit {rc}, no JSON on stdout: {err.strip()}")
    return rc, result


def expect_verify(tool, bundle, want_status):
    rc, res = verify_json(tool, bundle)
    want_rc = 0 if want_status == "OK" else 1
    expect(res.get("status") == want_status and rc == want_rc,
           f"verify: want {want_status}/exit {want_rc}, got {res.get('status')}/exit {rc}")


def external_setup(alg, tool):
    """Python-generated key pair on disk + trusted via our CLI; returns (key, keyid)."""
    key = alg.generate_key()
    (tool.workdir / "ext.key.pem").write_bytes(private_pem(key))
    (tool.workdir / "ext.pub.pem").write_bytes(public_pem(key.public_key()))
    (tool.workdir / ARTIFACT).write_bytes(b"interop artifact for " + alg.NAME.encode())
    out = tool.must("trust", "add", "-store", "trust.json", "-key", "ext.pub.pem",
                    "-package", PACKAGE)
    kid = keyid_of(key.public_key())
    expect(kid in out, f"trust add printed a different keyid (python: {kid})")
    return key, kid


def write_external_bundle(alg, tool, key, kid, name, signer=None):
    manifest = gb.manifest_for_file(tool.workdir / ARTIFACT, PACKAGE, VERSION, alg.NAME, kid)
    signature = (signer or alg.sign)(key, manifest)
    gb.write_bundle(tool.workdir / name, manifest, signature)
    return manifest, signature


# ---- external -> sister-sign ---------------------------------------------------------------------

def case_import_keys(alg, tool):
    key, kid = external_setup(alg, tool)
    out = tool.must("sign", "-file", ARTIFACT, "-package", PACKAGE, "-version", VERSION,
                    "-key", "ext.key.pem", "-out", "ours.bundle.json")
    expect(parse_field(out, "keyid") == kid, "sign derived a different keyid from the python key")
    manifest, sig, _ = gb.read_bundle(tool.workdir / "ours.bundle.json")
    alg.verify(key.public_key(), manifest, sig)
    return f"keyid {kid[:12]}… matches"


def case_import_bundle(alg, tool):
    key, kid = external_setup(alg, tool)
    _, sig = write_external_bundle(alg, tool, key, kid, "ext.bundle.json")
    expect_verify(tool, "ext.bundle.json", "OK")
    # Sanity: the same bundle with one flipped signature bit must be rejected.
    tampered = bytearray(sig)
    tampered[len(tampered) // 2] ^= 0x01
    manifest = gb.manifest_for_file(tool.workdir / ARTIFACT, PACKAGE, VERSION, alg.NAME, kid)
    gb.write_bundle(tool.workdir / "bad.bundle.json", manifest, bytes(tampered))
    expect_verify(tool, "bad.bundle.json", "INVALID_SIGNATURE")
    return f"OK; flipped bit -> INVALID_SIGNATURE ({len(sig)}-byte sig)"


# ---- sister-sign -> external ---------------------------------------------------------------------

def case_export_keys(alg, tool):
    out = tool.must("keygen", "-algorithm", alg.NAME, "-out", "ours")
    priv = serialization.load_pem_private_key((tool.workdir / "ours.key.pem").read_bytes(), None)
    pub = serialization.load_pem_public_key((tool.workdir / "ours.pub.pem").read_bytes())
    expect(public_pem(priv.public_key()) == public_pem(pub), "pub.pem does not belong to key.pem")
    kid = keyid_of(pub)
    expect(parse_field(out, "keyid") == kid, f"keygen keyid differs from python ({kid})")
    # The exported private key must be usable by the independent signer.
    alg.verify(pub, b"probe", alg.sign(priv, b"probe"))
    return f"PKCS#8 + SPKI loaded, keyid {kid[:12]}… matches"


def case_export_bundle(alg, tool):
    tool.must("keygen", "-algorithm", alg.NAME, "-out", "ours")
    (tool.workdir / ARTIFACT).write_bytes(b"artifact signed by sister-sign, " + alg.NAME.encode())
    tool.must("sign", "-file", ARTIFACT, "-package", PACKAGE, "-version", VERSION,
              "-key", "ours.key.pem", "-out", "ours.bundle.json")

    pub = serialization.load_pem_public_key((tool.workdir / "ours.pub.pem").read_bytes())
    manifest, sig, m = gb.read_bundle(tool.workdir / "ours.bundle.json")
    expected = gb.manifest_for_file(tool.workdir / ARTIFACT, PACKAGE, VERSION, alg.NAME,
                                    keyid_of(pub))
    expect(manifest == expected, f"manifest differs from independent build: {manifest!r}")
    alg.verify(pub, manifest, sig)
    try:
        alg.verify(pub, manifest.replace(VERSION.encode(), b"9.9.9"), sig)
        raise CaseFailed("python accepted the signature over a modified manifest")
    except InvalidSignature:
        pass

    detail = "cryptography OK"
    (tool.workdir / "manifest.bin").write_bytes(manifest)
    ok = openssl_verify(tool.workdir,
                        alg.openssl_args("ours.pub.pem", "manifest.bin", sig, tool.workdir))
    if ok is None:
        detail += ", openssl CLI not installed (skipped)"
    else:
        expect(ok, "openssl CLI rejected the signature")
        detail += ", openssl CLI OK"
    return detail + f" ({m['artifact']['size']} B artifact)"


# ---- algorithm-specific --------------------------------------------------------------------------

def case_ecdsa_der_conversion(alg, tool):
    key = alg.generate_key()
    der = alg.sign_der(key, b"message")
    raw = alg.der_to_raw(der)
    expect(len(raw) == 64, f"r||s is {len(raw)} bytes")
    expect(alg.raw_to_der(raw) == der, "DER -> r||s -> DER is not the identity")
    alg.verify(key.public_key(), b"message", raw)
    return f"DER {len(der)} B <-> r||s 64 B"


def case_ecdsa_raw_der_rejected(alg, tool):
    key, kid = external_setup(alg, tool)
    # A mathematically valid signature, but in DER instead of r||s.
    write_external_bundle(alg, tool, key, kid, "der.bundle.json", signer=alg.sign_der)
    expect_verify(tool, "der.bundle.json", "INVALID_SIGNATURE")
    return "valid DER signature -> INVALID_SIGNATURE"


def case_rsa_salt_pinned(alg, tool):
    key, kid = external_setup(alg, tool)
    # PSS with maximum salt (a common library default) verifies mathematically but is off-profile.
    write_external_bundle(alg, tool, key, kid, "salt.bundle.json",
                          signer=lambda k, m: alg.sign(k, m, salt_length=alg.MAX_SALT))
    expect_verify(tool, "salt.bundle.json", "INVALID_SIGNATURE")
    return "salt=max -> INVALID_SIGNATURE (only salt=32 accepted)"


CASES = [
    (TO_US, "keys: python key used by trust add + sign", case_import_keys),
    (TO_US, "bundle: python-made bundle verified by sister-sign", case_import_bundle),
    (FROM_US, "keys: keygen output loaded by python", case_export_keys),
    (FROM_US, "bundle: sister-sign bundle verified externally", case_export_bundle),
]
EXTRA_CASES = {
    ecdsa_p256_sha256.NAME: [
        ("format", "DER <-> r||s conversion", case_ecdsa_der_conversion),
        (TO_US, "raw DER signature rejected", case_ecdsa_raw_der_rejected),
    ],
    rsa_pss_sha256.NAME: [
        (TO_US, "PSS salt length pinned to 32", case_rsa_salt_pinned),
    ],
}


def main(argv):
    if len(argv) not in (2, 3):
        print(__doc__, file=sys.stderr)
        return 2
    binary = Path(argv[1]).resolve()
    if not binary.is_file():
        print(f"sister-sign binary not found: {binary}", file=sys.stderr)
        return 2
    if len(argv) == 3:
        out_dir = Path(argv[2]).resolve()
        shutil.rmtree(out_dir, ignore_errors=True)
        out_dir.mkdir(parents=True)
    else:
        out_dir = Path(tempfile.mkdtemp(prefix="sister-sign-interop-"))

    print(f"openssl CLI: {OPENSSL or 'not found (openssl checks skipped)'}")
    results = Results()
    for i, alg in enumerate(ALGORITHMS, 1):
        print(f"[{i}/{len(ALGORITHMS)}] {alg.NAME}")
        # Bind loop variables explicitly; each case gets a fresh work directory.
        for n, (direction, name, fn) in enumerate(CASES + EXTRA_CASES.get(alg.NAME, []), 1):
            workdir = out_dir / alg.NAME / f"{n:02d}"
            workdir.mkdir(parents=True)
            tool = Tool(binary, workdir)
            results.run(alg.NAME, direction, name, lambda fn=fn, alg=alg, tool=tool: fn(alg, tool))

    table = results.markdown()
    (out_dir / "results.md").write_text(table)
    print()
    print(table)
    print(f"evidence: {out_dir}")
    return 1 if results.failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
