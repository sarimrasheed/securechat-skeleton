"""
X.509 validation: signed-by-CA, validity window, CN/SAN.

This module is responsible for:
- Loading X.509 certificates (PEM)
- Verifying that a peer's certificate is signed by our Root CA
- Checking the validity window (not before / not after)
- Ensuring the Common Name (CN) or SAN matches the expected hostname
"""

from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID, ExtensionOID


# ---------------------------------------------------------
# Certificate Loading
# ---------------------------------------------------------

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


# ---------------------------------------------------------
# CA Signature Verification
# ---------------------------------------------------------

def verify_signed_by_ca(cert: x509.Certificate, ca_cert: x509.Certificate) -> bool:
    """
    Check that `cert` is signed by `ca_cert`.
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
        return False


# ---------------------------------------------------------
# Validity Window (timezone-aware)
# ---------------------------------------------------------

def verify_validity_window(cert: x509.Certificate, now: datetime | None = None) -> bool:
    """
    Check that the certificate is currently valid.
    Avoid offset-naive / offset-aware comparison issues.
    """

    # Always use timezone-aware UTC timestamp
    if now is None:
        now = datetime.now(timezone.utc)

    # Convert cert fields to timezone-aware versions
    not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
    not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

    return not_before <= now <= not_after


# ---------------------------------------------------------
# CN / SAN Validation
# ---------------------------------------------------------

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
    Extract DNS names from the Subject Alternative Name (SAN), if present.
    """
    names: list[str] = []
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san = san.value
        for entry in san.get_values_for_type(x509.DNSName):
            names.append(entry)
    except x509.ExtensionNotFound:
        return names
    except Exception:
        return names

    return names


def verify_name_matches(cert: x509.Certificate, expected_hostname: str) -> bool:
    """
    Ensure certificate CN or SAN DNS contains expected hostname.
    """
    cn = extract_common_name(cert)
    if cn == expected_hostname:
        return True

    san_names = extract_dns_san_names(cert)
    if expected_hostname in san_names:
        return True

    return False


# ---------------------------------------------------------
# Main Validation Entry Point
# ---------------------------------------------------------

def validate_peer_certificate_from_bytes(
    peer_cert_pem: bytes,
    ca_cert_path: str,
    expected_hostname: str,
) -> bool:
    """
    Validate that the peer certificate is:
    - Signed by our CA
    - Within the validity period
    - CN/SAN matches expected hostname
    """
    # Load peer certificate
    peer_cert = load_pem_certificate_from_bytes(peer_cert_pem)

    # Load trusted CA certificate
    ca_cert = load_pem_certificate(ca_cert_path)

    # 1) Signature chain
    if not verify_signed_by_ca(peer_cert, ca_cert):
        return False

    # 2) Validity window (timezone-aware)
    if not verify_validity_window(peer_cert):
        return False

    # 3) CN or SAN must match expected hostname
    if not verify_name_matches(peer_cert, expected_hostname):
        return False

    return True
