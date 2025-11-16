"""
SECURE CHAT CLIENT
Implements:
1) HELLO + certificate
2) Validate server cert
3) DH → AES-128 login key
4) Encrypted REGISTER
5) Encrypted LOGIN
6) Replay LOGIN (to test REPLAY protection)
"""

import socket
import json
import base64
import os

from dotenv import load_dotenv   # NEW

from app.crypto.pki import validate_peer_certificate_from_bytes
from app.crypto.dh import (
    dh_generate_private,
    dh_compute_public,
    dh_compute_shared,
    derive_aes_key,
)
from app.crypto.aes import aes_encrypt_ecb
from app.common.utils import now_ms, b64e, b64d


# ---------------------------------------------------------
# Load environment variables
# ---------------------------------------------------------
load_dotenv()   # NEW

CLIENT_CERT_PATH = os.getenv("CLIENT_CERT_PATH", "certs/client.cert.pem")
CA_CERT_PATH     = os.getenv("CA_CERT_PATH", "certs/ca/ca.cert.pem")
SERVER_HOST      = os.getenv("SERVER_HOST", "localhost")
SERVER_PORT      = int(os.getenv("SERVER_PORT", 5555))


def load_file(path: str):
    with open(path, "rb") as f:
        return f.read()


def int_to_bytes(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def send_enc(sock, key, kind, payload):
    plain = json.dumps(payload).encode()
    cipher = aes_encrypt_ecb(key, plain)

    msg = {
        "type": "enc",
        "kind": kind,
        "ciphertext": b64e(cipher),
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

    # ------------------------------------------------
    # 1) HELLO
    # ------------------------------------------------
    cert = load_file(CLIENT_CERT_PATH)
    hello = {
        "type": "hello",
        "cert": cert.decode(),
        "nonce": base64.b64encode(os.urandom(16)).decode(),
        "ts": now_ms(),
    }
    sock.sendall(json.dumps(hello).encode())
    print("[CLIENT] HELLO sent.")

    # ------------------------------------------------
    # 2) HELLO_ACK
    # ------------------------------------------------
    ack = recv_json(sock)
    if ack["type"] != "hello_ack":
        print("[CLIENT] Bad HELLO_ACK")
        return

    print("[CLIENT] Validating server certificate...")

    ok = validate_peer_certificate_from_bytes(
        ack["cert"].encode(),
        ca_cert_path=CA_CERT_PATH,
        expected_hostname="server.local"
    )

    if not ok:
        print("[CLIENT] BAD_CERT")
        return

    print("[CLIENT] Server cert OK.")

    # ------------------------------------------------
    # 3) DH Init
    # ------------------------------------------------
    client_priv = dh_generate_private()
    client_pub = dh_compute_public(client_priv)

    dh_init = {
        "type": "dh_init",
        "pub": b64e(int_to_bytes(client_pub)),
        "ts": now_ms(),
    }

    sock.sendall(json.dumps(dh_init).encode())
    print("[CLIENT] Sent dh_init.")

    # ------------------------------------------------
    # 4) DH Reply
    # ------------------------------------------------
    reply = recv_json(sock)
    server_pub = bytes_to_int(b64d(reply["pub"]))

    shared = dh_compute_shared(client_priv, server_pub)
    k_temp = derive_aes_key(shared)

    print(f"[CLIENT] DH key established ({len(k_temp)} bytes).")

    # ------------------------------------------------
    # 5) REGISTER
    # ------------------------------------------------
    reg = {
        "email": "alice@example.com",
        "username": "alice",
        "password": "password123",
    }

    print("[CLIENT] Sending encrypted REGISTER...")
    send_enc(sock, k_temp, "register", reg)

    print("[CLIENT] REGISTER response:", recv_json(sock))

    # ------------------------------------------------
    # 6) LOGIN
    # ------------------------------------------------
    login = {
        "username": "alice",
        "password": "password123",
    }

    print("[CLIENT] Sending encrypted LOGIN...")
    send_enc(sock, k_temp, "login", login)

    print("[CLIENT] LOGIN response:", recv_json(sock))

    # ------------------------------------------------
    # 7) REPLAY attack
    # ------------------------------------------------
    print("[CLIENT] Sending REPLAYED LOGIN...")
    send_enc(sock, k_temp, "login", login)

    print("[CLIENT] Replay response:", recv_json(sock))

    sock.close()
    print("[CLIENT] Closed.")

if __name__ == "__main__":
    main()

