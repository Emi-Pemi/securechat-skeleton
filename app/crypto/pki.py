#"""X.509 validation: signed-by-CA, validity window, CN/SAN.""" 
#raise NotImplementedError("students: implement PKI checks")

"""X.509 certificate validation: CA signature, validity period, CN check."""

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import datetime
import hashlib


def load_certificate(cert_pem: str) -> x509.Certificate:
    """
    Load X.509 certificate from PEM string.
    
    Args:
        cert_pem: Certificate in PEM format (string)
    
    Returns:
        Certificate object
    """
    return x509.load_pem_x509_certificate(
        cert_pem.encode('utf-8'),
        default_backend()
    )


def load_certificate_from_file(cert_path: str) -> x509.Certificate:
    """Load certificate from file."""
    with open(cert_path, 'rb') as f:
        return x509.load_pem_x509_certificate(f.read(), default_backend())


def load_private_key_from_file(key_path: str):
    """Load private key from file."""
    with open(key_path, 'rb') as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )


def validate_certificate(cert: x509.Certificate, ca_cert: x509.Certificate, expected_cn: str = None) -> tuple[bool, str]:
    """
    Validate certificate against CA.
    
    Checks:
    1. Signature chain validity (signed by CA)
    2. Validity period (not expired, not before valid)
    3. Common Name match (if expected_cn provided)
    
    Args:
        cert: Certificate to validate
        ca_cert: Trusted CA certificate
        expected_cn: Expected Common Name (optional)
    
    Returns:
        tuple: (is_valid, error_message)
    """
    try:
        # Check 1: Validity period
        now = datetime.datetime.utcnow()
        
        if now < cert.not_valid_before:
            return False, "BAD_CERT: Certificate not yet valid"
        
        if now > cert.not_valid_after:
            return False, "BAD_CERT: Certificate has expired"
        
        # Check 2: Verify signature (cert signed by CA)
        try:
            ca_public_key = ca_cert.public_key()
            ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )
        except Exception as e:
            return False, f"BAD_CERT: Invalid signature - {str(e)}"
        
        # Check 3: Issuer matches CA subject
        if cert.issuer != ca_cert.subject:
            return False, "BAD_CERT: Certificate not issued by trusted CA"
        
        # Check 4: Common Name (if specified)
        if expected_cn:
            try:
                cert_cn_attrs = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
                if not cert_cn_attrs:
                    return False, "BAD_CERT: Certificate has no Common Name"
                
                cert_cn = cert_cn_attrs[0].value
                if cert_cn != expected_cn:
                    return False, f"BAD_CERT: CN mismatch - expected '{expected_cn}', got '{cert_cn}'"
            except Exception as e:
                return False, f"BAD_CERT: Error checking CN - {str(e)}"
        
        return True, "Certificate valid"
        
    except Exception as e:
        return False, f"BAD_CERT: Validation error - {str(e)}"


def get_certificate_fingerprint(cert: x509.Certificate) -> str:
    """
    Get SHA-256 fingerprint of certificate.
    
    Args:
        cert: Certificate
    
    Returns:
        Hex string of fingerprint
    """
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(cert_der).hexdigest()


def get_common_name(cert: x509.Certificate) -> str:
    """Extract Common Name from certificate."""
    try:
        cn_attrs = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        if cn_attrs:
            return cn_attrs[0].value
        return "Unknown"
    except:
        return "Unknown"


def cert_to_pem_string(cert: x509.Certificate) -> str:
    """Convert certificate to PEM string."""
    return cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
