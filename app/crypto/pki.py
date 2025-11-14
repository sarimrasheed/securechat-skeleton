"""
X.509 validation: signed-by-CA, validity window, CN/SAN.

This module is responsible for:
- Loading X.509 certificates (PEM)
- Verifying that a peer's certificate is signed by our Root CA
- Checking the validity window (not before / not after)
- Ensuring the Common Name (CN) or SAN matches the expected hostname
"""

from datetime import datetime
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID, ExtensionOID


def load_pem_certificate(path: str) -> x509.Certificate:
    """
    Load an X.509 certificate from a PEM file.
    """
    pem_path = Path(path)
    with pem_path.open("rb") as f:
        data = f.read()
    return x509.load_pem_x509_certificate(data)


def load_pem_certificate_from_bytes(pem_bytes: bytes) -> x509.Certificate:
    """
    Load an X.509 certificate from PEM-encoded bytes (as received over the network).
    """
    return x509.load_pem_x509_certificate(pem_bytes)


def verify_signed_by_ca(cert: x509.Certificate, ca_cert: x509.Certificate) -> bool:
    """
    Check that `cert` is signed by `ca_cert`.

    This verifies the certificate's signature using the CA's public key.
    """
    try:
        ca_public_key = ca_cert.public_key()
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        return True
    except InvalidSignature:
        return False
    except Exception:
        # Any parsing / unexpected error -> treat as invalid
        return False


def verify_validity_window(cert: x509.Certificate, now: datetime | None = None) -> bool:
    """
    Check that the certificate is currently valid (not expired, not in the future).
    """
    if now is None:
        now = datetime.utcnow()

    # If now is outside [not_valid_before, not_valid_after], cert is invalid.
    if now < cert.not_valid_before or now > cert.not_valid_after:
        return False
    return True


def extract_common_name(cert: x509.Certificate) -> str | None:
    """
    Extract the Common Name (CN) from the certificate's subject.
    """
    try:
        attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not attrs:
            return None
        return attrs[0].value
    except Exception:
        return None


def extract_dns_san_names(cert: x509.Certificate) -> list[str]:
    """
    Extract DNS names from the Subject Alternative Name (SAN) extension, if present.
    """
    names: list[str] = []
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san = san.value  # SubjectAlternativeName
        for entry in san.get_values_for_type(x509.DNSName):
            names.append(entry)
    except x509.ExtensionNotFound:
        # SAN not present is not fatal, we just return an empty list
        return names
    except Exception:
        return names

    return names


def verify_name_matches(cert: x509.Certificate, expected_hostname: str) -> bool:
    """
    Check that either:
    - CN == expected_hostname
    OR
    - expected_hostname is present in SAN DNS names.
    """
    cn = extract_common_name(cert)
    if cn == expected_hostname:
        return True

    san_names = extract_dns_san_names(cert)
    if expected_hostname in san_names:
        return True

    return False


def validate_peer_certificate_from_bytes(
    peer_cert_pem: bytes,
    ca_cert_path: str,
    expected_hostname: str,
) -> bool:
    """
    MAIN ENTRY POINT for client/server code.

    Parameters:
        peer_cert_pem: the PEM-encoded certificate bytes received from the peer.
        ca_cert_path: path to our Root CA certificate (e.g. 'certs/ca/ca.cert.pem').
        expected_hostname: what we expect in CN / SAN (e.g. 'server.local').

    Returns:
        True if the peer certificate is:
            - signed by our CA
            - currently valid
            - CN or SAN matches expected_hostname
        False otherwise.
    """
    # 1) Load peer cert from PEM bytes
    peer_cert = load_pem_certificate_from_bytes(peer_cert_pem)

    # 2) Load our trusted CA certificate from disk
    ca_cert = load_pem_certificate(ca_cert_path)

    # 3) Verify signature chain (peer signed by CA)
    if not verify_signed_by_ca(peer_cert, ca_cert):
        return False

    # 4) Verify validity window
    if not verify_validity_window(peer_cert):
        return False

    # 5) Verify CN or SAN matches expected hostname
    if not verify_name_matches(peer_cert, expected_hostname):
        return False

    return True
