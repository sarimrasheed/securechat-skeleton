"""
Pydantic models for all protocol messages used in the Secure Chat System.

NOTE:
The client/server implementation uses raw JSON dicts for socket communication.
However, the assignment skeleton requires these models for documentation,
validation, and testing purposes.

Models include:
- HELLO / HELLO_ACK
- DH_INIT / DH_REPLY
- ENC_MESSAGE (register/login/chat)
- SESSION_DH_INIT / SESSION_DH_REPLY
- SESSION_RECEIPT
"""

from pydantic import BaseModel
from typing import Optional


# ---------------------------------------------------------
# 1. HELLO (Client → Server)
# ---------------------------------------------------------

class Hello(BaseModel):
    type: str = "hello"
    cert: str     # PEM-encoded certificate (string)
    nonce: str
    ts: int       # timestamp (ms)


# ---------------------------------------------------------
# 2. HELLO_ACK (Server → Client)
# ---------------------------------------------------------

class HelloAck(BaseModel):
    type: str = "hello_ack"
    cert: str
    nonce: str
    ts: int


# ---------------------------------------------------------
# 3. DH_INIT (Client → Server)
# ---------------------------------------------------------

class DHInit(BaseModel):
    type: str = "dh_init"
    pub: str     # base64 of DH public
    ts: int


# ---------------------------------------------------------
# 4. DH_REPLY (Server → Client)
# ---------------------------------------------------------

class DHReply(BaseModel):
    type: str = "dh_reply"
    pub: str     # base64 of DH public
    ts: int


# ---------------------------------------------------------
# 5. SIGNED + ENCRYPTED MESSAGE (REGISTER / LOGIN / CHAT)
# ---------------------------------------------------------

class EncMessage(BaseModel):
    type: str = "enc"
    kind: str              # "register" | "login" | "chat"
    ciphertext: str        # Base64 AES ciphertext
    sig: str               # Base64 RSA signature
    ts: int                # timestamp for replay protection


# ---------------------------------------------------------
# 6. Session DH (after LOGIN)
# ---------------------------------------------------------

class SessionDHInit(BaseModel):
    type: str = "session_dh_init"
    pub: str
    ts: int


class SessionDHReply(BaseModel):
    type: str = "session_dh_reply"
    pub: str
    ts: int


# ---------------------------------------------------------
# 7. SessionReceipt (Non-Repudiation)
# ---------------------------------------------------------

class SessionReceipt(BaseModel):
    client: str
    server: str
    transcript_hash: str
    signed_by: str
    sig: str      # Base64 RSA signature of transcript hash
