from hashlib import sha256

from ecdsa import SECP256k1, SigningKey
from ecdsa.numbertheory import inverse_mod
from ecdsa.util import sigdecode_string

if __name__ == "__main__":
    print("testing nonce reuse case")

    n = SECP256k1.order

    print(f"on curve: SECP256k1")

    k = 1337 # The example reused nonce

    print(f"with nonce: {k}")

    # Generate the key pair
    d_A = SigningKey.generate(curve=SECP256k1)
    original_private_key = d_A.privkey.secret_multiplier
    Q_A = d_A.verifying_key

    print(f"with private key: {original_private_key}")

    # Define messages
    m1 = b"first message"
    m2 = b"second message"

    print(f"using message 1: {m1}")
    print(f"using message 2: {m2}")

    # Sign message digests with the same nonce
    signature_1 = d_A.sign(m1, hashfunc=sha256, k=k)
    signature_2 = d_A.sign(m2, hashfunc=sha256, k=k)

    print(f"gives signature 1: {signature_1.hex()}")
    print(f"gives signature 2: {signature_2.hex()}")

    # Get signature components
    r1, s1 = sigdecode_string(signature_1, n)
    r2, s2 = sigdecode_string(signature_2, n)

    # Calculate message digests
    h1 = int(sha256(m1).hexdigest(), base=16)
    h2 = int(sha256(m2).hexdigest(), base=16)

    # Recover private key
    recovered_private_key = ((s2 * h1 - s1 * h2) * inverse_mod(r1 * (s1 - s2), n)) % n

    print(f"with derivable private key: {recovered_private_key}")

    assert(original_private_key == recovered_private_key)


    print("testing known nonce case")

    n = SECP256k1.order

    print(f"on curve: SECP256k1")

    k = 1337 # The example known nonce

    print(f"with nonce: {k}")

    # Generate the key pair
    d_A = SigningKey.generate(curve=SECP256k1)
    original_private_key = d_A.privkey.secret_multiplier
    Q_A = d_A.verifying_key

    print(f"with private key: {original_private_key}")

    # Define message
    m = b"message"

    print(f"using message: {m}")

    # Sign message digest with known nonce
    signature = d_A.sign(m, hashfunc=sha256, k=k)

    print(f"gives signature: {signature.hex()}")

    # Get signature components
    r, s = sigdecode_string(signature, n)

    # Calculate message digest
    h = int(sha256(m).hexdigest(), base=16)

    # Recover private key
    recovered_private_key = ((s * k - h) * inverse_mod(r, n)) % n

    print(f"with derivable private key: {recovered_private_key}")

    assert(original_private_key == recovered_private_key)
