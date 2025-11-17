#"""RSA PKCS#1 v1.5 SHA-256 sign/verify.""" 
#raise NotImplementedError("students: implement RSA helpers")

"""RSA digital signatures using SHA-256 with PKCS#1 v1.5 padding."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


def sign_data(data: bytes, private_key) -> bytes:
    """
    Sign data using RSA private key with SHA-256.
    
    Args:
        data: Data to sign (bytes)
        private_key: RSA private key object
    
    Returns:
        Signature as bytes
    """
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature


def verify_signature(data: bytes, signature: bytes, public_key) -> bool:
    """
    Verify RSA signature using public key.
    
    Args:
        data: Original data that was signed
        signature: Signature to verify
        public_key: RSA public key (from certificate)
    
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


def compute_message_digest(seqno: int, timestamp: int, ciphertext: bytes) -> bytes:
    """
    Compute SHA-256 digest for message signing.
    digest = SHA256(seqno || timestamp || ciphertext)
    
    Args:
        seqno: Sequence number
        timestamp: Unix timestamp in milliseconds
        ciphertext: Encrypted message bytes
    
    Returns:
        SHA-256 digest as bytes
    """
    import hashlib
    
    # Convert integers to bytes (big-endian)
    seqno_bytes = seqno.to_bytes(8, byteorder='big')
    ts_bytes = timestamp.to_bytes(8, byteorder='big')
    
    # Concatenate and hash
    data = seqno_bytes + ts_bytes + ciphertext
    digest = hashlib.sha256(data).digest()
    
    return digest
