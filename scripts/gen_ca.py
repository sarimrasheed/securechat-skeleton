"""
Create Root CA (RSA + self-signed X.509) using cryptography.
"""

import argparse
import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate_root_ca(cn: str, out_dir: Path) -> None:
    """
    Generate a Root Certificate Authority.
    Produces:
        ca.key.pem  (private key)
        ca.cert.pem (self-signed certificate)
    """
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1. Generate private key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # 2. Build X.509 certificate (self-signed CA)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NU Root CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )

    now = datetime.datetime.utcnow()

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))  # ~10 years
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )

    # 3. Write to disk
    key_path = out_dir / "ca.key.pem"
    cert_path = out_dir / "ca.cert.pem"

    with key_path.open("wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with cert_path.open("wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"[OK] CA private key written to {key_path}")
    print(f"[OK] CA certificate written to {cert_path}")


def main():
    parser = argparse.ArgumentParser(description="Generate Root CA")
    parser.add_argument("--name", required=True, help="Common Name (CN)")
    args = parser.parse_args()

    out_dir = Path("certs") / "ca"
    generate_root_ca(args.name, out_dir)


if __name__ == "__main__":
    main()
