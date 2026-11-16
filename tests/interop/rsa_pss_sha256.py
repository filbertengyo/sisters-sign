"""RSA-PSS 3072, e=65537, SHA-256, MGF1-SHA-256, salt length 32 bytes."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

NAME = "rsa-pss-sha256"
SALT_LEN = 32
MAX_SALT = padding.PSS.MAX_LENGTH  # a common library default; not accepted by our profile


def _pss(salt_length=SALT_LEN):
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=salt_length)


def generate_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


def sign(private_key, message, salt_length=SALT_LEN):
    return private_key.sign(message, _pss(salt_length), hashes.SHA256())


def verify(public_key, message, signature):
    """Raises cryptography.exceptions.InvalidSignature on failure."""
    if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size != 3072:
        raise TypeError("not an RSA-3072 public key")
    public_key.verify(signature, message, _pss(), hashes.SHA256())


def openssl_args(pub, msg, sig_bytes, workdir):
    (workdir / "openssl.sig").write_bytes(sig_bytes)
    return ["dgst", "-sha256", "-sigopt", "rsa_padding_mode:pss",
            "-sigopt", f"rsa_pss_saltlen:{SALT_LEN}", "-sigopt", "rsa_mgf1_md:sha256",
            "-verify", pub, "-signature", "openssl.sig", msg]
