#"""AES-128(ECB)+PKCS#7 helpers (use library).""" 
#raise NotImplementedError("students: implement AES helpers")

"""AES-128 encryption/decryption with PKCS#7 padding using CBC mode."""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os


def pad_pkcs7(data: bytes, block_size: int = 16) -> bytes:
    """Apply PKCS#7 padding to data"""
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding


def unpad_pkcs7(data: bytes) -> bytes:
    """Remove PKCS#7 padding from data"""
    if len(data) == 0:
        raise ValueError("Cannot unpad empty data")
    padding_length = data[-1]
    if padding_length > len(data) or padding_length > 16:
        raise ValueError("Invalid padding")
    # Verify all padding bytes are correct
    for i in range(padding_length):
        if data[-(i+1)] != padding_length:
            raise ValueError("Invalid padding")
    return data[:-padding_length]


def aes_encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt plaintext using AES-128 CBC with PKCS#7 padding.
    
    Args:
        plaintext: Data to encrypt
        key: 16-byte AES-128 key
    
    Returns:
        tuple: (iv, ciphertext)
    """
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes for AES-128")
    
    # Apply PKCS#7 padding
    padded = pad_pkcs7(plaintext)
    
    # Generate random IV
    iv = os.urandom(16)
    
    # Create cipher and encrypt
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    
    return iv, ciphertext


def aes_decrypt(iv: bytes, ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt AES-128 CBC ciphertext and remove PKCS#7 padding.
    
    Args:
        iv: 16-byte initialization vector
        ciphertext: Encrypted data
        key: 16-byte AES-128 key
    
    Returns:
        plaintext as bytes
    """
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes for AES-128")
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes")
    
    # Create cipher and decrypt
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove PKCS#7 padding
    plaintext = unpad_pkcs7(padded)
    
    return plaintext


def encrypt_message(message: str, key: bytes) -> tuple[bytes, bytes]:
    """
    Convenience function to encrypt a string message.
    
    Returns:
        tuple: (iv, ciphertext)
    """
    return aes_encrypt(message.encode('utf-8'), key)


def decrypt_message(iv: bytes, ciphertext: bytes, key: bytes) -> str:
    """
    Convenience function to decrypt to a string message.
    
    Returns:
        Decrypted message as string
    """
    plaintext = aes_decrypt(iv, ciphertext, key)
    return plaintext.decode('utf-8')
