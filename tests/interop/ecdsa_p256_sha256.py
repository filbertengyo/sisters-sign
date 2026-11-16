"""ECDSA P-256 + SHA-256. On the wire the signature is 64 bytes r||s (big-endian, 32 bytes each),
while OpenSSL / Python `cryptography` produce and expect ASN.1 DER. The conversion lives here."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

NAME = "ecdsa-p256-sha256"
SCALAR_LEN = 32


def der_to_raw(der):
    r, s = decode_dss_signature(der)
    return r.to_bytes(SCALAR_LEN, "big") + s.to_bytes(SCALAR_LEN, "big")


def raw_to_der(raw):
    if len(raw) != 2 * SCALAR_LEN:
        raise ValueError(f"r||s must be {2 * SCALAR_LEN} bytes, got {len(raw)}")
    return encode_dss_signature(
        int.from_bytes(raw[:SCALAR_LEN], "big"), int.from_bytes(raw[SCALAR_LEN:], "big")
    )


def generate_key():
    return ec.generate_private_key(ec.SECP256R1())


def sign_der(private_key, message):
    return private_key.sign(message, ec.ECDSA(hashes.SHA256()))


def sign(private_key, message):
    return der_to_raw(sign_der(private_key, message))


def verify(public_key, message, signature):
    """Raises cryptography.exceptions.InvalidSignature on failure."""
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or public_key.curve.name != "secp256r1":
        raise TypeError("not a P-256 public key")
    public_key.verify(raw_to_der(signature), message, ec.ECDSA(hashes.SHA256()))


def openssl_args(pub, msg, sig_bytes, workdir):
    (workdir / "openssl.sig").write_bytes(raw_to_der(sig_bytes))  # openssl dgst wants DER
    return ["dgst", "-sha256", "-verify", pub, "-signature", "openssl.sig", msg]
