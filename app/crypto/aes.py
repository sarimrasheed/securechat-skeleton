# app/crypto/aes.py
"""
AES-128 (ECB) with PKCS#7 padding.
Used for encrypted REGISTER + LOGIN in Assignment 2.

IMPORTANT:
- AES-ECB is NOT secure for real systems.
- You are required by the assignment to use AES-128 ECB only
  for the secure-login channel (after DH key agreement).

Functions:
- pkcs7_pad(data)
- pkcs7_unpad(padded)
- aes_encrypt_ecb(key, plaintext)
- aes_decrypt_ecb(key, ciphertext)
"""

from Crypto.Cipher import AES
from typing import Final

BLOCK_SIZE: Final[int] = 16  # AES block size (128 bits)


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """
    Apply PKCS#7 padding.
    If data length is exactly a multiple of block_size,
    a full block of padding is added.
    """
    pad_len = block_size - (len(data) % block_size)
    pad_len = pad_len if pad_len != 0 else block_size
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(padded: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """
    Remove PKCS#7 padding.
    Raises ValueError if padding is malformed.
    """
    if len(padded) == 0 or len(padded) % block_size != 0:
        raise ValueError("Invalid padded length for PKCS#7.")

    pad_len = padded[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid PKCS#7 pad length.")

    if padded[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS#7 pad bytes.")

    return padded[:-pad_len]


def aes_encrypt_ecb(key: bytes, plaintext: bytes) -> bytes:
    """
    AES-128 ECB encrypt with PKCS#7 padding.
    - key must be 16 bytes.
    """
    if len(key) != 16:
        raise ValueError("AES-128 key must be exactly 16 bytes.")

    cipher = AES.new(key, AES.MODE_ECB)
    padded = pkcs7_pad(plaintext, BLOCK_SIZE)
    return cipher.encrypt(padded)


def aes_decrypt_ecb(key: bytes, ciphertext: bytes) -> bytes:
    """
    AES-128 ECB decrypt and PKCS#7 unpad.
    - key must be 16 bytes.
    - ciphertext must be multiple of block size.
    """
    if len(key) != 16:
        raise ValueError("AES-128 key must be exactly 16 bytes.")

    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext not aligned to AES block size.")

    cipher = AES.new(key, AES.MODE_ECB)
    padded = cipher.decrypt(ciphertext)
    return pkcs7_unpad(padded, BLOCK_SIZE)
