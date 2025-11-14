"""
Generate server/client certificates signed by Root CA.
Usage examples:
    python scripts/gen_cert.py --cn server.local --name server
    python scripts/gen_cert.py --cn client.local --name client
"""

import argparse
import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def load_ca(ca_dir: Path):
    ca_key = serialization.load_pem_private_key(
        (ca_dir / "ca.key.pem").read_bytes(), password=None
    )

    ca_cert = x509.load_pem_x509_certificate(
        (ca_dir / "ca.cert.pem").read_bytes()
    )

    return ca_key, ca_cert


def generate_cert(cn: str, name: str, ca_dir: Path):
    out_key = Path(f"certs/{name}.key.pem")
    out_cert = Path(f"certs/{name}.cert.pem")

    out_key.parent.mkdir(parents=True, exist_ok=True)

    ca_key, ca_cert = load_ca(ca_dir)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    now = datetime.datetime.utcnow()

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat Entity"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )

    # Write key
    out_key.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    # Write certificate
    out_cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    print(f"[OK] Generated {out_key}")
    print(f"[OK] Generated {out_cert}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cn", required=True)
    parser.add_argument("--name", required=True)
    args = parser.parse_args()

    generate_cert(args.cn, args.name, Path("certs/ca"))


if __name__ == "__main__":
    main()
