"""
Helper signatures: now_ms, b64e, b64d, sha256_hex.
"""

import time
import base64
import hashlib


def now_ms() -> int:
    """Return current UNIX time in milliseconds."""
    return int(time.time() * 1000)


def b64e(b: bytes) -> str:
    """Base64 encode bytes → UTF-8 string."""
    return base64.b64encode(b).decode()


def b64d(s: str) -> bytes:
    """Base64 decode string → raw bytes."""
    return base64.b64decode(s.encode())


def sha256_hex(data: bytes) -> str:
    """Return SHA-256 digest as hex string."""
    return hashlib.sha256(data).hexdigest()
