SecureChat – Assignment A02

CS-3002 Information Security – Fall 2025
Author: Sarim Rasheed (22i-1280)

1. Overview

This project implements a fully custom, TLS-free Secure Chat System as required by Assignment A02.
The protocol and cryptographic logic are implemented entirely at the application layer, without using SSL/TLS, OpenSSL sockets, or HTTPS.

The system demonstrates all four CIANR security properties:

Confidentiality – AES-128 encrypted login + chat messages

Integrity – RSA SHA256 signatures + PKCS#7 padding

Authenticity – Full PKI (Root CA → server cert → client cert)

Non-Repudiation – Signed SessionReceipt + append-only transcript

The project implements:

✔ Secure MySQL credential store
✔ Salted SHA-256 password hashing
✔ HELLO / HELLO_ACK with certificates + timestamps
✔ Mutual certificate validation (CN/SAN enforced)
✔ Temporary DH key → AES-128 encrypted REGISTER + LOGIN
✔ RSA signatures on all encrypted fields
✔ Session transcript + transcript hash
✔ Signed SessionReceipt
✔ Replay attack prevention
✔ Secret-free GitHub repository

2. Directory Structure
securechat-skeleton/
├── app/
│   ├── client.py
│   ├── server.py
│   ├── crypto/
│   │   ├── aes.py
│   │   ├── dh.py
│   │   ├── pki.py
│   │   ├── sign.py
│   ├── common/
│   │   ├── protocol.py
│   │   ├── utils.py
│   ├── storage/
│       ├── db.py
│       ├── transcript.py
├── certs/
│   ├── ca/
│   │   ├── ca.key.pem
│   │   ├── ca.cert.pem
│   ├── client.cert.pem
│   ├── client.key.pem
│   ├── server.cert.pem
│   ├── server.key.pem
├── transcripts/      # ignored by git
├── scripts/
│   ├── gen_ca.py
│   ├── gen_cert.py
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md

3. Environment Setup
Install dependencies
pip install -r requirements.txt

Create the database

Create a MySQL database:

CREATE DATABASE securechat;
CREATE USER 'scuser'@'localhost' IDENTIFIED BY 'scpass';
GRANT ALL PRIVILEGES ON securechat.* TO 'scuser'@'localhost';


Initialize the users table:

python -m app.storage.db --init

4. Generating Certificates (PKI)
Step 1 — Create Root CA
python scripts/gen_ca.py --name "FAST-NU Root CA"


This generates:

certs/ca/ca.key.pem
certs/ca/ca.cert.pem

Step 2 — Create Server Certificate
python scripts/gen_cert.py --cn server.local --name server

Step 3 — Create Client Certificate
python scripts/gen_cert.py --cn client.local --name client

5. Running the System
Start the server
python -m app.server


Expected output:

[SERVER] Listening on localhost:5555...
[SERVER] Connection from ...
[SERVER] Certificate OK.
[SERVER] Session complete.

Run the client
python -m app.client


Expected output:

[CLIENT] HELLO sent.
[CLIENT] Server cert OK.
[CLIENT] K_temp established.
[CLIENT] REGISTER response: register_ok
[CLIENT] LOGIN response: login_ok
[CLIENT] K_session established.
[CLIENT] SessionReceipt received.

6. Security Features Summary
Security Property	Achieved Through
Confidentiality	AES-128 (ECB) using DH-derived keys
Integrity	RSA SHA-256 message signatures
Authenticity	Full PKI validation + CN/SAN matching
Non-Repudiation	Signed SessionReceipt + transcripts
Replay Protection	Timestamp checking on all encrypted messages
7. Academic Integrity

This repository contains:

✔ No private keys
✔ No .env
✔ No transcripts
✔ No secrets

All logic is implemented manually at the application layer as required.

8. Author

Sarim Rasheed (22i-1280)
FAST-NUCES, Islamabad
CS-3002 — Information Security
Assignment A02 – Secure Chat System