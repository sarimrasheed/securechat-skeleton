"""
SECURE CHAT CLIENT — FINAL (A02 COMPLETE)

Implements:
1) HELLO + cert
2) Validate server certificate
3) Temp DH → K_temp
4) REGISTER (signed + encrypted)
5) LOGIN (signed + encrypted)
6) Session DH → K_session
7) Encrypted CHAT message (signed)
8) Receive SessionReceipt
"""

import socket
import json
import base64
import os

from dotenv import load_dotenv

from app.crypto.pki import validate_peer_certificate_from_bytes
from app.crypto.dh import (
    dh_generate_private,
    dh_compute_public,
    dh_compute_shared,
    derive_aes_key,
)
from app.crypto.aes import aes_encrypt_ecb
from app.crypto.sign import rsa_sign
from app.common.utils import now_ms, b64e, b64d

load_dotenv()

CLIENT_CERT_PATH = os.getenv("CLIENT_CERT_PATH", "certs/client.cert.pem")
CLIENT_PRIV_KEY = os.getenv("CLIENT_PRIVATE_KEY", "certs/client.key.pem")
CA_CERT_PATH = os.getenv("CA_CERT_PATH", "certs/ca/ca.cert.pem")
SERVER_HOST = os.getenv("SERVER_HOST", "localhost")
SERVER_PORT = int(os.getenv("SERVER_PORT", 5555))


def load_file(path: str):
    with open(path, "rb") as f:
        return f.read()


def int_to_bytes(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def send_signed_encrypted(sock, key, kind, payload):
    """Encrypt JSON + attach RSA signature."""
    plain = json.dumps(payload).encode()
    sig = rsa_sign(CLIENT_PRIV_KEY, plain)
    cipher = aes_encrypt_ecb(key, plain)

    msg = {
        "type": "enc",
        "kind": kind,
        "ciphertext": b64e(cipher),
        "sig": sig,
        "ts": now_ms(),
    }
    sock.sendall(json.dumps(msg).encode())


def recv_json(sock):
    data = sock.recv(20000)
    if not data:
        return None
    return json.loads(data.decode())


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SERVER_HOST, SERVER_PORT))
    print(f"[CLIENT] Connected to {SERVER_HOST}:{SERVER_PORT}.")

    # --------------------------------------------------
    # HELLO
    # --------------------------------------------------
    cert = load_file(CLIENT_CERT_PATH)
    hello = {
        "type": "hello",
        "cert": cert.decode(),
        "nonce": base64.b64encode(os.urandom(16)).decode(),
        "ts": now_ms(),
    }
    sock.sendall(json.dumps(hello).encode())
    print("[CLIENT] HELLO sent.")

    # --------------------------------------------------
    # HELLO_ACK
    # --------------------------------------------------
    ack = recv_json(sock)
    print("[CLIENT] Validating server certificate...")
    ok = validate_peer_certificate_from_bytes(
        ack["cert"].encode(),
        ca_cert_path=CA_CERT_PATH,
        expected_hostname="server.local",
    )
    if not ok:
        print("[CLIENT] BAD_CERT — aborting")
        return

    print("[CLIENT] Server cert OK.")

    # --------------------------------------------------
    # DH → K_temp
    # --------------------------------------------------
    client_priv = dh_generate_private()
    client_pub = dh_compute_public(client_priv)

    dh_init = {
        "type": "dh_init",
        "pub": b64e(int_to_bytes(client_pub)),
        "ts": now_ms(),
    }
    sock.sendall(json.dumps(dh_init).encode())

    dh_reply = recv_json(sock)
    server_pub = bytes_to_int(b64d(dh_reply["pub"]))

    shared = dh_compute_shared(client_priv, server_pub)
    k_temp = derive_aes_key(shared)
    print("[CLIENT] K_temp established (login key).")

    # --------------------------------------------------
    # REGISTER
    # --------------------------------------------------
    reg = {
        "email": "alice@example.com",
        "username": "alice",
        "password": "password123",
    }

    print("[CLIENT] Sending REGISTER...")
    send_signed_encrypted(sock, k_temp, "register", reg)
    print("[CLIENT] REGISTER response:", recv_json(sock))

    # --------------------------------------------------
    # LOGIN
    # --------------------------------------------------
    login = {
        "username": "alice",
        "password": "password123",
    }

    print("[CLIENT] Sending LOGIN...")
    send_signed_encrypted(sock, k_temp, "login", login)
    print("[CLIENT] LOGIN response:", recv_json(sock))

    # --------------------------------------------------
    # Session DH → K_session
    # --------------------------------------------------
    print("[CLIENT] Performing Session DH...")
    c2_priv = dh_generate_private()
    c2_pub = dh_compute_public(c2_priv)

    sock.sendall(json.dumps({
        "type": "session_dh_init",
        "pub": b64e(int_to_bytes(c2_pub)),
        "ts": now_ms(),
    }).encode())

    reply = recv_json(sock)
    s2_pub = bytes_to_int(b64d(reply["pub"]))
    shared2 = dh_compute_shared(c2_priv, s2_pub)
    k_session = derive_aes_key(shared2)

    print("[CLIENT] K_session established.")

    # --------------------------------------------------
    # Encrypted CHAT message
    # --------------------------------------------------
    message = {"msg": "Hello secure world!"}
    print("[CLIENT] Sending encrypted CHAT...")
    send_signed_encrypted(sock, k_session, "chat", message)

    # --------------------------------------------------
    # Receive SessionReceipt
    # --------------------------------------------------
    receipt = recv_json(sock)
    print("[CLIENT] SessionReceipt received:")
    print(receipt)

    sock.close()
    print("[CLIENT] Closed.")


if __name__ == "__main__":
    main()
