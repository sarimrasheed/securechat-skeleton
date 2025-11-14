"""
Classic DH helpers + Trunc16(SHA256(Ks)) derivation.
Implements:
- dh_generate_private()
- dh_compute_public()
- dh_compute_shared()
- derive_aes_key()
"""

import os
import hashlib

# Use a 2048-bit MODP Group (RFC 3526 - Group 14)
P = int("""
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
29024E088A67CC74020BBEA63B139B22514A08798E3404DD
EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245
E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381
FFFFFFFFFFFFFFFF
""".replace("\n", "").replace(" ", ""), 16)

G = 2  # Generator


def dh_generate_private():
    """
    Generate a 256-bit private DH exponent.
    """
    return int.from_bytes(os.urandom(32), "big")


def dh_compute_public(a: int) -> int:
    """
    Compute DH public value A = g^a mod p.
    """
    return pow(G, a, P)


def dh_compute_shared(private_a: int, public_b: int) -> int:
    """
    Compute shared secret: s = (public_b ^ private_a) mod p.
    """
    return pow(public_b, private_a, P)


def derive_aes_key(shared_secret: int) -> bytes:
    """
    Derive a 16-byte AES-128 key from the DH shared secret.

    K_temp = Trunc16(SHA256(shared_secret_bytes))
    """
    # convert integer to bytes
    b = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, "big")

    # SHA256 digest
    digest = hashlib.sha256(b).digest()

    # return first 16 bytes (AES-128 key)
    return digest[:16]
