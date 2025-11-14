"""
Server workflow — implements:
1) Listen on TCP
2) Receive client HELLO (+ client cert)
3) Validate client certificate using our Root CA
4) Send server HELLO_ACK (+ server cert)
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


SERVER_CERT_PATH = "certs/server.cert.pem"
SERVER_KEY_PATH = "certs/server.key.pem"
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
    # 1. Create TCP server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("localhost", 5555))
    server_socket.listen(5)

    print("[SERVER] Listening on port 5555...")

    while True:
        conn, addr = server_socket.accept()
        print(f"[SERVER] Connection from {addr}")

        try:
            # 2. Receive HELLO from client
            data = conn.recv(10000).decode()
            if not data:
                print("[SERVER] Empty data, closing.")
                conn.close()
                continue

            msg = json.loads(data)

            if msg.get("type") != "hello":
                print("[SERVER] Invalid first message")
                conn.close()
                continue

            client_cert_pem = msg["cert"].encode()

            # 3. Validate client certificate
            print("[SERVER] Validating client certificate...")

            valid = validate_peer_certificate_from_bytes(
                peer_cert_pem=client_cert_pem,
                ca_cert_path=CA_CERT_PATH,
                expected_hostname="client.local",
            )

            if not valid:
                print("[SERVER] BAD_CERT – closing connection.")
                conn.sendall(b"BAD_CERT")
                conn.close()
                continue

            print("[SERVER] Certificate OK.")

            # 4. Send HELLO_ACK with SERVER cert
            server_cert_pem = load_file(SERVER_CERT_PATH)
            server_nonce = base64.b64encode(b"server-nonce").decode()

            hello_ack = {
                "type": "hello_ack",
                "cert": server_cert_pem.decode(),
                "nonce": server_nonce,
                "ts": now_ms(),
            }

            conn.sendall(json.dumps(hello_ack).encode())
            print("[SERVER] HELLO_ACK sent.")

            # 5. Receive client's DH init
            data = conn.recv(10000).decode()
            if not data:
                print("[SERVER] No DH_INIT received, closing.")
                conn.close()
                continue

            dh_msg = json.loads(data)
            if dh_msg.get("type") != "dh_init":
                print("[SERVER] Expected dh_init, got:", dh_msg.get("type"))
                conn.close()
                continue

            print("[SERVER] Received dh_init from client.")

            client_pub_b64 = dh_msg["pub"]
            client_pub_bytes = b64d(client_pub_b64)
            client_pub_int = bytes_to_int(client_pub_bytes)

            # 6. Generate server DH private/public
            server_priv = dh_generate_private()
            server_pub_int = dh_compute_public(server_priv)

            # 7. Compute shared secret
            shared_secret = dh_compute_shared(server_priv, client_pub_int)
            k_temp = derive_aes_key(shared_secret)

            print(f"[SERVER] Temporary DH key established (len={len(k_temp)} bytes).")

            # 8. Send server DH public value back
            server_pub_bytes = int_to_bytes(server_pub_int)
            server_pub_b64 = b64e(server_pub_bytes)

            dh_reply = {
                "type": "dh_reply",
                "pub": server_pub_b64,
                "ts": now_ms(),
            }

            conn.sendall(json.dumps(dh_reply).encode())
            print("[SERVER] Sent dh_reply to client.")

            # NOTE: For now, we just establish K_temp.
            # In the next phase, we will use k_temp for encrypted registration/login.

            # Keep connection open for next steps (login, chat) later,
            # but for now we can close after DH test.
            conn.close()
            print("[SERVER] Connection closed after temporary DH.")

        except Exception as e:
            print("[SERVER] Error:", e)
            conn.close()


if __name__ == "__main__":
    main()
