"""
Issue server/client certificates signed by Root CA.
"""

import argparse
import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def load_ca(ca_dir: Path):
    key_path = ca_dir / "ca.key.pem"
    cert_path = ca_dir / "ca.cert.pem"

    with key_path.open("rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)

    with cert_path.open("rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    return ca_key, ca_cert


def generate_cert(cn: str, out_prefix: Path, ca_dir: Path):
    """
    Generates:
       <out_prefix>.key.pem
       <out_prefix>.cert.pem
    signed by CA located in ca_dir.
    """
    out_prefix.parent.mkdir(parents=True, exist_ok=True)

    ca_key, ca_cert = load_ca(ca_dir)

    # 1. Generate keypair
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat Entity"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )

    now = datetime.datetime.utcnow()

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(cn)]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    key_path = out_prefix.with_suffix(".key.pem")
    cert_path = out_prefix.with_suffix(".cert.pem")

    # Write key
    with key_path.open("wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Write cert
    with cert_path.open("wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"[OK] Private key written to {key_path}")
    print(f"[OK] Certificate written to {cert_path}")


def main():
    parser = argparse.ArgumentParser(description="Generate server/client cert")
    parser.add_argument("--cn", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--ca-dir", default="certs/ca")
    args = parser.parse_args()

    generate_cert(args.cn, Path(args.out), Path(args.ca_dir))


if __name__ == "__main__":
    main()
