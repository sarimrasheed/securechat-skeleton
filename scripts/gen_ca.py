"""
Generate Root CA (RSA + self-signed X.509).
Outputs:
    certs/ca/ca.key.pem
    certs/ca/ca.cert.pem
"""

import argparse
import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate_root_ca(cn: str, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    # Generate CA private key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    now = datetime.datetime.utcnow()

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NU Root CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    # Write outputs
    (out_dir / "ca.key.pem").write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    (out_dir / "ca.cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    print("[OK] Generated certs/ca/ca.key.pem")
    print("[OK] Generated certs/ca/ca.cert.pem")


def main():
    parser = argparse.ArgumentParser(description="Generate Root CA")
    parser.add_argument("--name", required=True)
    args = parser.parse_args()

    out_dir = Path("certs/ca")
    generate_root_ca(args.name, out_dir)


if __name__ == "__main__":
    main()
