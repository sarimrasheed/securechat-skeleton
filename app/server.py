"""
SECURE CHAT SERVER — FINAL (A02 COMPLETE + FIXED)
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
from app.crypto.aes import aes_decrypt_ecb
from app.crypto.sign import rsa_verify, rsa_load_private_key
from app.common.utils import now_ms, b64e, b64d

from app.storage.db import create_user, verify_user
from app.storage.transcript import (
    append_entry,
    compute_transcript_hash,
    save_session_receipt,
)

load_dotenv()

SERVER_CERT_PATH = os.getenv("SERVER_CERT_PATH", "certs/server.cert.pem")
SERVER_PRIV_KEY = os.getenv("SERVER_PRIVATE_KEY", "certs/server.key.pem")
CA_CERT_PATH = os.getenv("CA_CERT_PATH", "certs/ca/ca.cert.pem")
SERVER_HOST = os.getenv("SERVER_HOST", "localhost")
SERVER_PORT = int(os.getenv("SERVER_PORT", 5555))


def load_file(path):
    with open(path, "rb") as f:
        return f.read()


def int_to_bytes(n: int) -> bytes:
    return n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b"\x00"


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def recv_json(conn):
    data = conn.recv(20000)
    if not data:
        return None
    return json.loads(data.decode())


def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_HOST, SERVER_PORT))
    server_socket.listen(5)

    print(f"[SERVER] Listening on {SERVER_HOST}:{SERVER_PORT}...")

    while True:
        conn, addr = server_socket.accept()
        session_id = f"{addr[0]}_{addr[1]}_{now_ms()}"
        print(f"[SERVER] Connection from {addr}")

        try:
            # ------------------------------------------------------
            # HELLO
            # ------------------------------------------------------
            msg = recv_json(conn)
            client_cert_pem = msg["cert"].encode()

            print("[SERVER] Validating client certificate...")

            ok = validate_peer_certificate_from_bytes(
                peer_cert_pem=client_cert_pem,
                ca_cert_path=CA_CERT_PATH,
                #
                expected_hostname="client.local",
            )
            if not ok:
                conn.sendall(json.dumps({"type": "BAD_CERT"}).encode())
                conn.close()
                continue

            print("[SERVER] Certificate OK.")

            server_cert_pem = load_file(SERVER_CERT_PATH)
            conn.sendall(json.dumps({
                "type": "hello_ack",
                "cert": server_cert_pem.decode(),
                "nonce": base64.b64encode(os.urandom(16)).decode(),
                "ts": now_ms(),
            }).encode())

            # ------------------------------------------------------
            # Temp DH
            # ------------------------------------------------------
            dh_msg = recv_json(conn)
            client_pub = bytes_to_int(b64d(dh_msg["pub"]))

            s_priv = dh_generate_private()
            s_pub = dh_compute_public(s_priv)

            shared = dh_compute_shared(s_priv, client_pub)
            k_temp = derive_aes_key(shared)

            conn.sendall(json.dumps({
                "type": "dh_reply",
                "pub": b64e(int_to_bytes(s_pub)),
                "ts": now_ms(),
            }).encode())

            last_seen_ts = 0

            def check_replay(ts):
                nonlocal last_seen_ts
                if ts <= last_seen_ts:
                    return False
                last_seen_ts = ts
                return True

            # ------------------------------------------------------
            # REGISTER
            # ------------------------------------------------------
            msg = recv_json(conn)

            if not check_replay(msg["ts"]):
                conn.sendall(json.dumps({"type": "REPLAY"}).encode())
                continue

            cipher = b64d(msg["ciphertext"])
            sig = msg["sig"]
            plain = aes_decrypt_ecb(k_temp, cipher)

            if not rsa_verify("certs/client.cert.pem", plain, sig):
                conn.sendall(json.dumps({"type": "SIG_FAIL"}).encode())
                continue

            reg = json.loads(plain.decode())
            append_entry(session_id, {"dir": "client", **msg})

            ok = create_user(reg["email"], reg["username"], reg["password"])
            conn.sendall(json.dumps({
                "type": "register_ok" if ok else "register_fail"
            }).encode())

            # ------------------------------------------------------
            # LOGIN
            # ------------------------------------------------------
            msg = recv_json(conn)

            if not check_replay(msg["ts"]):
                conn.sendall(json.dumps({"type": "REPLAY"}).encode())
                continue

            cipher = b64d(msg["ciphertext"])
            sig = msg["sig"]
            plain = aes_decrypt_ecb(k_temp, cipher)

            if not rsa_verify("certs/client.cert.pem", plain, sig):
                conn.sendall(json.dumps({"type": "SIG_FAIL"}).encode())
                continue

            login = json.loads(plain.decode())
            append_entry(session_id, {"dir": "client", **msg})

            ok = verify_user(login["username"], login["password"])
            conn.sendall(json.dumps({
                "type": "login_ok" if ok else "login_fail"
            }).encode())

            # ------------------------------------------------------
            # REPLAYED LOGIN HANDLING
            # ------------------------------------------------------
            replay_msg = recv_json(conn)

            if replay_msg and replay_msg.get("type") == "enc":
                # This is the replayed login from the client
                if not check_replay(replay_msg["ts"]):
                    conn.sendall(json.dumps({"type": "REPLAY"}).encode())
                else:
                    conn.sendall(json.dumps({"type": "UNEXPECTED"}).encode())
            # Now move on to session DH normally

            # ------------------------------------------------------
            # Session DH
            # ------------------------------------------------------
            info = recv_json(conn)

            if not info or info.get("type") != "session_dh_init":
                print("[SERVER] Expected session_dh_init, got:", info)
                conn.close()
                continue

            c2_pub = bytes_to_int(b64d(info["pub"]))

            s2_priv = dh_generate_private()
            s2_pub = dh_compute_public(s2_priv)

            shared2 = dh_compute_shared(s2_priv, c2_pub)
            k_session = derive_aes_key(shared2)

            conn.sendall(json.dumps({
                "type": "session_dh_reply",
                "pub": b64e(int_to_bytes(s2_pub)),
                "ts": now_ms(),
            }).encode())

            # ------------------------------------------------------
            # CHAT
            # ------------------------------------------------------
            msg = recv_json(conn)
            append_entry(session_id, {"dir": "client", **msg})

            # ------------------------------------------------------
            # SessionReceipt
            # ------------------------------------------------------
            th = compute_transcript_hash(session_id)

            priv = rsa_load_private_key(SERVER_PRIV_KEY)
            from Crypto.Signature import pkcs1_15
            from Crypto.Hash import SHA256

            h = SHA256.new(th.encode())
            sig = pkcs1_15.new(priv).sign(h)

            receipt = {
                "client": "client.local",
                "server": "server.local",
                "transcript_hash": th,
                "signed_by": "server",
                "sig": base64.b64encode(sig).decode(),
            }

            save_session_receipt(session_id, receipt)
            conn.sendall(json.dumps(receipt).encode())

            conn.close()
            print("[SERVER] Session complete.\n")

        except Exception as e:
            print("[SERVER] Error:", e)
            conn.close()


if __name__ == "__main__":
    main()
