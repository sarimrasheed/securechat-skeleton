"""
SECURE CHAT CLIENT — FINAL (A02 COMPLETE & MATCHED WITH SERVER)
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
    return n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b"\x00"


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def send_signed_encrypted(sock, key, kind, payload):
    """
    Encrypt JSON and attach RSA signature.
    Returns the message dict (used for replay test).
    """
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
    return msg


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
        "nonce": b64e(os.urandom(16)),
        "ts": now_ms(),
    }

    sock.sendall(json.dumps(hello).encode())
    print("[CLIENT] HELLO sent.")

    # --------------------------------------------------
    # HELLO_ACK + BAD_CERT HANDLING
    # --------------------------------------------------
    ack = recv_json(sock)

    if ack is None:
        print("[CLIENT] No HELLO_ACK received — aborting.")
        sock.close()
        return

    if ack.get("type") == "BAD_CERT":
        print("[CLIENT] Server rejected our certificate (BAD_CERT).")
        sock.close()
        return

    if "cert" not in ack:
        print("[CLIENT] HELLO_ACK missing certificate — aborting.")
        sock.close()
        return

    print("[CLIENT] Validating server certificate...")

    ok = validate_peer_certificate_from_bytes(
        ack["cert"].encode(),
        ca_cert_path=CA_CERT_PATH,
        expected_hostname="server.local",
    )

    if not ok:
        print("[CLIENT] BAD_CERT — aborting.")
        sock.close()
        return

    print("[CLIENT] Server cert OK.")

    # --------------------------------------------------
    # DH → K_temp
    # --------------------------------------------------
    client_priv = dh_generate_private()
    client_pub = dh_compute_public(client_priv)

    sock.sendall(json.dumps({
        "type": "dh_init",
        "pub": b64e(int_to_bytes(client_pub)),
        "ts": now_ms()
    }).encode())

    dh_reply = recv_json(sock)

    if dh_reply is None:
        print("[CLIENT] No DH reply — aborting.")
        sock.close()
        return

    shared = dh_compute_shared(
        client_priv,
        bytes_to_int(b64d(dh_reply["pub"]))
    )

    k_temp = derive_aes_key(shared)
    print("[CLIENT] K_temp established (login key).")

    # --------------------------------------------------
    # REGISTER (Dynamic Input)
    # --------------------------------------------------
    print("\n=== REGISTER ===")
    email = input("Enter email: ")
    username = input("Enter username: ")
    password = input("Enter password: ")

    reg = {"email": email, "username": username, "password": password}

    print("[CLIENT] Sending REGISTER...")
    send_signed_encrypted(sock, k_temp, "register", reg)
    print("[CLIENT] REGISTER response:", recv_json(sock))

    # --------------------------------------------------
    # LOGIN (Dynamic Input)
    # --------------------------------------------------
    print("\n=== LOGIN ===")
    login_user = input("Enter username: ")
    login_pass = input("Enter password: ")

    login = {"username": login_user, "password": login_pass}

    print("[CLIENT] Sending LOGIN...")
    login_msg = send_signed_encrypted(sock, k_temp, "login", login)
    print("[CLIENT] LOGIN response:", recv_json(sock))

    # --------------------------------------------------
    # SIG_FAIL test — tamper ciphertext
    # --------------------------------------------------
    print("[CLIENT] Sending TAMPERED encrypted LOGIN...")

    tampered = login_msg.copy()
    tampered["ciphertext"] = tampered["ciphertext"][:-4] + "ABCD"

    sock.sendall(json.dumps(tampered).encode())
    sig_fail_resp = recv_json(sock)
    print("[CLIENT] SIG_FAIL response:", sig_fail_resp)

    # --------------------------------------------------
    # REPLAY TEST
    # --------------------------------------------------
    print("[CLIENT] Sending REPLAYED LOGIN...")
    sock.sendall(json.dumps(login_msg).encode())
    replay_resp = recv_json(sock)
    print("[CLIENT] Replay response:", replay_resp)

    if replay_resp is None:
        print("[CLIENT] Server closed connection during replay test.")
        sock.close()
        return

    # --------------------------------------------------
    # Session DH → K_session
    # --------------------------------------------------
    print("[CLIENT] Performing Session DH...")

    c2_priv = dh_generate_private()
    c2_pub = dh_compute_public(c2_priv)

    sock.sendall(json.dumps({
        "type": "session_dh_init",
        "pub": "INVALID_PUB_VALUE",  # For DH ERROR TEST
        "ts": now_ms()
    }).encode())

    reply = recv_json(sock)

    if reply is None:
        print("[CLIENT] Server closed connection unexpectedly.")
        sock.close()
        return

    s2_pub = bytes_to_int(b64d(reply["pub"]))
    shared2 = dh_compute_shared(c2_priv, s2_pub)
    k_session = derive_aes_key(shared2)

    print("[CLIENT] K_session established.")

    # --------------------------------------------------
    # Encrypted CHAT
    # --------------------------------------------------
    message = {"msg": "Hello secure world!"}
    print("[CLIENT] Sending encrypted CHAT...")
    send_signed_encrypted(sock, k_session, "chat", message)

    # --------------------------------------------------
    # SessionReceipt
    # --------------------------------------------------
    receipt = recv_json(sock)
    print("[CLIENT] SessionReceipt received:")
    print(receipt)

    sock.close()
    print("[CLIENT] Closed.")


if __name__ == "__main__":
    main()
