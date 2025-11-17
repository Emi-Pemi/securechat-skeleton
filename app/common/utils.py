#"""Helper signatures: now_ms, b64e, b64d, sha256_hex."""

#def now_ms(): raise NotImplementedError

#def b64e(b: bytes): raise NotImplementedError

#def b64d(s: str): raise NotImplementedError

#def sha256_hex(data: bytes): raise NotImplementedError

"""Helper signatures: now_ms, b64e, b64d, sha256_hex."""

import base64
import hashlib
import time


def now_ms():
    """Return current Unix timestamp in milliseconds"""
    return int(time.time() * 1000)


def b64e(b: bytes):
    """Base64 encode bytes and return as string"""
    return base64.b64encode(b).decode('utf-8')


def b64d(s: str):
    """Base64 decode string and return as bytes"""
    return base64.b64decode(s)


def sha256_hex(data: bytes):
    """Compute SHA-256 hash and return as hex string"""
    return hashlib.sha256(data).hexdigest()