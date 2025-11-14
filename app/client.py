"""
Client workflow — implements:
1) Connect to server
2) Send HELLO (+ client cert)
3) Receive HELLO_ACK (+ server cert)
4) Validate server certificate
5) Perform temporary Diffie–Hellman to derive AES-128 login key
"""

import socket
import json
import base64

from app.crypto.pki import validate_peer_certificate_from_bytes
from app.crypto.dh import (
    dh_generate_private,
    dh_compute_public,
    dh_compute_shared,
    derive_aes_key,
)
from app.common.utils import now_ms, b64e, b64d


CLIENT_CERT_PATH = "certs/client.cert.pem"
CLIENT_KEY_PATH = "certs/client.key.pem"
CA_CERT_PATH = "certs/ca/ca.cert.pem"


def load_file(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def int_to_bytes(n: int) -> bytes:
    """Convert integer to big-endian bytes."""
    if n == 0:
        return b"\x00"
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def bytes_to_int(b: bytes) -> int:
    """Convert big-endian bytes to integer."""
    return int.from_bytes(b, "big")


def main():
    # 1. Connect to server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("localhost", 5555))

    print("[CLIENT] Connected to server.")

    # 2. Send HELLO
    client_cert_pem = load_file(CLIENT_CERT_PATH)
    client_nonce = base64.b64encode(b"client-nonce").decode()

    hello_msg = {
        "type": "hello",
        "cert": client_cert_pem.decode(),
        "nonce": client_nonce,
        "ts": now_ms(),
    }

    sock.sendall(json.dumps(hello_msg).encode())
    print("[CLIENT] HELLO sent.")

    # 3. Receive HELLO_ACK
    data = sock.recv(10000).decode()
    if not data:
        print("[CLIENT] No HELLO_ACK received, closing.")
        sock.close()
        return

    msg = json.loads(data)

    if msg.get("type") == "BAD_CERT":
        print("[CLIENT] Server rejected our cert: BAD_CERT")
        sock.close()
        return

    if msg.get("type") != "hello_ack":
        print("[CLIENT] Invalid response, expected hello_ack, got:", msg.get("type"))
        sock.close()
        return

    server_cert_pem = msg["cert"].encode()

    # 4. Validate server certificate
    print("[CLIENT] Validating server certificate...")

    valid = validate_peer_certificate_from_bytes(
        peer_cert_pem=server_cert_pem,
        ca_cert_path=CA_CERT_PATH,
        expected_hostname="server.local",
    )

    if not valid:
        print("[CLIENT] BAD_CERT – invalid server certificate")
        sock.close()
        return

    print("[CLIENT] Server certificate OK.")

    # 5. Perform temporary Diffie–Hellman exchange
    print("[CLIENT] Starting temporary DH key exchange...")

    # Generate client DH private/public
    client_priv = dh_generate_private()
    client_pub_int = dh_compute_public(client_priv)
    client_pub_bytes = int_to_bytes(client_pub_int)
    client_pub_b64 = b64e(client_pub_bytes)

    dh_init = {
        "type": "dh_init",
        "pub": client_pub_b64,
        "ts": now_ms(),
    }

    sock.sendall(json.dumps(dh_init).encode())
    print("[CLIENT] Sent dh_init to server.")

    # Receive server DH reply
    data = sock.recv(10000).decode()
    if not data:
        print("[CLIENT] No dh_reply received, closing.")
        sock.close()
        return

    dh_reply = json.loads(data)
    if dh_reply.get("type") != "dh_reply":
        print("[CLIENT] Expected dh_reply, got:", dh_reply.get("type"))
        sock.close()
        return

    print("[CLIENT] Received dh_reply from server.")

    server_pub_b64 = dh_reply["pub"]
    server_pub_bytes = b64d(server_pub_b64)
    server_pub_int = bytes_to_int(server_pub_bytes)

    # Compute shared secret
    shared_secret = dh_compute_shared(client_priv, server_pub_int)
    k_temp = derive_aes_key(shared_secret)

    print(f"[CLIENT] Temporary DH key established (len={len(k_temp)} bytes).")

    # NOTE: Next phase will use k_temp for encrypted registration/login.
    # For now, we close connection after verifying DH works.
    sock.close()
    print("[CLIENT] Connection closed after temporary DH.")


if __name__ == "__main__":
    main()
