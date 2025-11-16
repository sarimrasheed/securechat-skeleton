"""
SECURE CHAT SERVER
Implements Option-C Requirements:
1) Mutual certificate validation
2) DH → AES-128 temporary login key
3) Encrypted REGISTER + LOGIN
4) Replay protection using timestamps
5) Rejects stale / repeated encrypted messages
"""

import socket
import json
import base64
import os
import time

from dotenv import load_dotenv  # NEW

from app.crypto.pki import validate_peer_certificate_from_bytes
from app.crypto.dh import (
    dh_generate_private,
    dh_compute_public,
    dh_compute_shared,
    derive_aes_key,
)
from app.crypto.aes import aes_decrypt_ecb
from app.common.utils import now_ms, b64e, b64d

from app.storage.db import create_user, verify_user

# ---------------------------------------------------------
# Load environment and config
# ---------------------------------------------------------
load_dotenv()  # NEW

SERVER_CERT_PATH = os.getenv("SERVER_CERT_PATH", "certs/server.cert.pem")
CA_CERT_PATH = os.getenv("CA_CERT_PATH", "certs/ca/ca.cert.pem")
SERVER_HOST = os.getenv("SERVER_HOST", "localhost")
SERVER_PORT = int(os.getenv("SERVER_PORT", 5555))


def load_file(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def int_to_bytes(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def recv_json(conn):
    data = conn.recv(20000)
    if not data:
        return None
    return json.loads(data.decode())


def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_HOST, SERVER_PORT))  # UPDATED
    server_socket.listen(5)

    print(f"[SERVER] Listening on {SERVER_HOST}:{SERVER_PORT}...")  # UPDATED

    while True:
        conn, addr = server_socket.accept()
        print(f"[SERVER] Connection from {addr}")

        try:
            # ------------------------------------------------------
            # 1) HELLO + client certificate
            # ------------------------------------------------------
            msg = recv_json(conn)
            if not msg or msg.get("type") != "hello":
                print("[SERVER] Invalid HELLO")
                conn.close()
                continue

            client_cert_pem = msg["cert"].encode()

            print("[SERVER] Validating client certificate...")

            ok = validate_peer_certificate_from_bytes(
                peer_cert_pem=client_cert_pem,
                ca_cert_path=CA_CERT_PATH,
                expected_hostname="client.local",
            )

            if not ok:
                print("[SERVER] BAD_CERT")
                conn.sendall(json.dumps({"type": "BAD_CERT"}).encode())
                conn.close()
                continue

            print("[SERVER] Certificate OK.")

            # ------------------------------------------------------
            # 2) HELLO_ACK + server certificate
            # ------------------------------------------------------
            server_cert_pem = load_file(SERVER_CERT_PATH)
            nonce = base64.b64encode(os.urandom(16)).decode()

            hello_ack = {
                "type": "hello_ack",
                "cert": server_cert_pem.decode(),
                "nonce": nonce,
                "ts": now_ms(),
            }

            conn.sendall(json.dumps(hello_ack).encode())
            print("[SERVER] Sent HELLO_ACK")

            # ------------------------------------------------------
            # 3) DH_INIT → compute shared AES key
            # ------------------------------------------------------
            dh_msg = recv_json(conn)
            if not dh_msg or dh_msg.get("type") != "dh_init":
                print("[SERVER] Expected dh_init")
                conn.close()
                continue

            client_pub = bytes_to_int(b64d(dh_msg["pub"]))

            # Generate server DH
            server_priv = dh_generate_private()
            server_pub = dh_compute_public(server_priv)

            shared = dh_compute_shared(server_priv, client_pub)
            k_temp = derive_aes_key(shared)

            print(f"[SERVER] DH key established ({len(k_temp)} bytes).")

            dh_reply = {
                "type": "dh_reply",
                "pub": b64e(int_to_bytes(server_pub)),
                "ts": now_ms(),
            }

            conn.sendall(json.dumps(dh_reply).encode())

            # ------------------------------------------------------
            # 4) REPLAY PROTECTION
            # ------------------------------------------------------
            last_seen_ts = 0

            def check_replay(ts: int) -> bool:
                nonlocal last_seen_ts
                if ts <= last_seen_ts:
                    return False
                last_seen_ts = ts
                return True

            # ------------------------------------------------------
            # 5) Encrypted REGISTER
            # ------------------------------------------------------
            msg = recv_json(conn)
            if not msg or msg.get("type") != "enc" or msg.get("kind") != "register":
                print("[SERVER] Expected encrypted REGISTER")
                conn.close()
                continue

            if not check_replay(msg["ts"]):
                conn.sendall(json.dumps({"type": "REPLAY_DETECTED"}).encode())
                conn.close()
                continue

            reg_plain = aes_decrypt_ecb(k_temp, b64d(msg["ciphertext"]))
            reg = json.loads(reg_plain.decode())

            print(f"[SERVER] REGISTER username={reg['username']}")

            ok = create_user(reg["email"], reg["username"], reg["password"])

            conn.sendall(json.dumps(
                {"type": "register_ok" if ok else "register_fail"}
            ).encode())

            # ------------------------------------------------------
            # 6) Encrypted LOGIN
            # ------------------------------------------------------
            msg = recv_json(conn)
            if not msg or msg.get("type") != "enc" or msg.get("kind") != "login":
                print("[SERVER] Expected encrypted LOGIN")
                conn.close()
                continue

            if not check_replay(msg["ts"]):
                conn.sendall(json.dumps({"type": "REPLAY_DETECTED"}).encode())
                conn.close()
                continue

            login_plain = aes_decrypt_ecb(k_temp, b64d(msg["ciphertext"]))
            login = json.loads(login_plain.decode())

            print(f"[SERVER] LOGIN username={login['username']}")

            ok = verify_user(login["username"], login["password"])
            conn.sendall(json.dumps(
                {"type": "login_ok" if ok else "login_fail"}
            ).encode())

            # ------------------------------------------------------
            # 7) Replay attack test (client will repeat same LOGIN)
            # ------------------------------------------------------
            replay = recv_json(conn)
            if replay:
                if not check_replay(replay["ts"]):
                    print("[SERVER] Replay detected.")
                    conn.sendall(json.dumps({"type": "REPLAY_DETECTED"}).encode())
                else:
                    conn.sendall(json.dumps({"type": "ERROR"}).encode())

            conn.close()
            print("[SERVER] Connection closed.\n")

        except Exception as e:
            print("[SERVER] Error:", e)
            conn.close()

    server_socket.close()

if __name__ == "__main__":
    main()