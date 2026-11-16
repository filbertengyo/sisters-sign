"""Ed25519 (pure, one-shot over the manifest bytes; signature = 64 bytes)."""

from cryptography.hazmat.primitives.asymmetric import ed25519

NAME = "ed25519"


def generate_key():
    return ed25519.Ed25519PrivateKey.generate()


def sign(private_key, message):
    return private_key.sign(message)


def verify(public_key, message, signature):
    """Raises cryptography.exceptions.InvalidSignature on failure."""
    if not isinstance(public_key, ed25519.Ed25519PublicKey):
        raise TypeError("not an Ed25519 public key")
    public_key.verify(signature, message)


def openssl_args(pub, msg, sig_bytes, workdir):
    (workdir / "openssl.sig").write_bytes(sig_bytes)
    return ["pkeyutl", "-verify", "-pubin", "-inkey", pub, "-rawin", "-in", msg,
            "-sigfile", "openssl.sig"]
