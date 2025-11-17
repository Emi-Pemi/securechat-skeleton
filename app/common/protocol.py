#"""Pydantic models: hello, server_hello, register, login, dh_client, dh_server, msg, receipt.""" 
#raise NotImplementedError("students: define pydantic models")

"""Pydantic message models for the SecureChat protocol."""

from pydantic import BaseModel
from typing import Optional


class HelloMessage(BaseModel):
    """Client hello message with certificate and nonce"""
    type: str = "hello"
    client_cert: str  # PEM format
    nonce: str  # base64


class ServerHelloMessage(BaseModel):
    """Server hello response with certificate and nonce"""
    type: str = "server_hello"
    server_cert: str  # PEM format
    nonce: str  # base64


class DHClientMessage(BaseModel):
    """Client DH parameters for key exchange"""
    type: str = "dh_client"
    g: int
    p: int
    A: int  # g^a mod p


class DHServerMessage(BaseModel):
    """Server DH response"""
    type: str = "dh_server"
    B: int  # g^b mod p


class RegisterMessage(BaseModel):
    """User registration message (sent encrypted under temp DH key)"""
    type: str = "register"
    email: str
    username: str
    pwd: str  # base64(sha256(salt||password))
    salt: str  # base64
    iv: str  # base64 - IV for AES encryption


class LoginMessage(BaseModel):
    """User login message (sent encrypted under temp DH key)"""
    type: str = "login"
    email: str
    pwd: str  # base64(sha256(salt||password))
    nonce: str  # base64
    iv: str  # base64 - IV for AES encryption


class AuthResponseMessage(BaseModel):
    """Server response to registration/login"""
    type: str = "auth_response"
    success: bool
    message: str
    iv: Optional[str] = None  # base64 - IV for AES encryption


class ChatMessage(BaseModel):
    """Encrypted chat message with signature"""
    type: str = "msg"
    seqno: int
    ts: int  # Unix timestamp in milliseconds
    ct: str  # base64 - ciphertext (includes IV prepended)
    sig: str  # base64 - RSA signature over SHA256(seqno||ts||ct)


class SessionReceipt(BaseModel):
    """Non-repudiation receipt for session transcript"""
    type: str = "receipt"
    peer: str  # "client" or "server"
    first_seq: int
    last_seq: int
    transcript_sha256: str  # hex
    sig: str  # base64 - RSA signature over transcript_sha256


class ErrorMessage(BaseModel):
    """Error message"""
    type: str = "error"
    code: str  # BAD_CERT, SIG_FAIL, REPLAY, etc.
    message: str