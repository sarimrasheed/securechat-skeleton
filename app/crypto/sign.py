# app/crypto/sign.py
"""
RSA Signing + Verification (SHA256 + PKCS#1 v1.5)
Used for message integrity + authenticity in Assignment 2.
"""

import base64
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA


def rsa_load_private_key(path: str):
    with open(path, "rb") as f:
        return RSA.import_key(f.read())


def rsa_load_public_key(path: str):
    with open(path, "rb") as f:
        return RSA.import_key(f.read())


def rsa_sign(private_key_path: str, message_bytes: bytes) -> str:
    """
    Returns base64 signature.
    """
    key = rsa_load_private_key(private_key_path)
    h = SHA256.new(message_bytes)
    sig = pkcs1_15.new(key).sign(h)
    return base64.b64encode(sig).decode()


def rsa_verify(public_key_path: str, message_bytes: bytes, signature_b64: str) -> bool:
    """
    Verify signature. Returns True/False.
    """
    try:
        key = rsa_load_public_key(public_key_path)
        sig = base64.b64decode(signature_b64)
        h = SHA256.new(message_bytes)
        pkcs1_15.new(key).verify(h, sig)
        return True
    except Exception:
        return False
