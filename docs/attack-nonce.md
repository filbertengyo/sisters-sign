# Nonce Reuse Attack

The script written in `tests/attacks/nonce_reuse.py` demonstrates both a nonce reuse and a known nonce attack to derive the private key. Reusing the same nonce on multiple signatures allows an attacker to calculate both the used nonce and the private key used. When the nonce is known, it is also possible for the attacker to derive the private key from just a signature, the public key, and the messaage. This is why a CSPRNG is required when generate nonces, ensuring that no nonce is reused and an attacker can't guess the next nonce.
