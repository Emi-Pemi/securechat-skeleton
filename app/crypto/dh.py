#"""Classic DH helpers + Trunc16(SHA256(Ks)) derivation.""" 
#raise NotImplementedError("students: implement DH helpers")

"""Classic Diffie-Hellman key exchange and key derivation."""

import secrets
import hashlib


class DHKeyExchange:
    """
    Diffie-Hellman key exchange using RFC 3526 Group 14 parameters.
    """
    
    # Safe prime p (2048-bit) - RFC 3526 Group 14
    P = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
    )
    
    G = 2  # Generator
    
    def __init__(self):
        """Initialize DH with random private key."""
        # Generate random private key (256-bit for efficiency)
        self.private_key = secrets.randbelow(self.P - 2) + 1
        # Compute public key: g^a mod p
        self.public_key = pow(self.G, self.private_key, self.P)
    
    def get_public_params(self) -> tuple[int, int, int]:
        """
        Get public DH parameters.
        
        Returns:
            tuple: (g, p, public_key)
        """
        return self.G, self.P, self.public_key
    
    def compute_shared_secret(self, peer_public_key: int) -> int:
        """
        Compute shared secret from peer's public key.
        
        Args:
            peer_public_key: Peer's public DH value (A or B)
        
        Returns:
            Shared secret K_s = peer_public^private mod p
        """
        if not (2 <= peer_public_key < self.P):
            raise ValueError("Invalid peer public key")
        
        return pow(peer_public_key, self.private_key, self.P)


def derive_aes_key(shared_secret: int) -> bytes:
    """
    Derive AES-128 key from DH shared secret.
    K = Trunc_16(SHA256(big-endian(K_s)))
    
    Args:
        shared_secret: Integer shared secret from DH
    
    Returns:
        16-byte AES-128 key
    """
    # Convert shared secret integer to big-endian bytes
    byte_length = (shared_secret.bit_length() + 7) // 8
    shared_secret_bytes = shared_secret.to_bytes(byte_length, byteorder='big')
    
    # Hash with SHA-256
    digest = hashlib.sha256(shared_secret_bytes).digest()
    
    # Truncate to 16 bytes for AES-128
    return digest[:16]
