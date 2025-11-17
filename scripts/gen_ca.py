#!/usr/bin/env python3
"""
Generate a self-signed Root Certificate Authority (CA)
This CA will be used to sign server and client certificates
"""

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import datetime
import os


def generate_root_ca():
    """Generate a self-signed root CA certificate and private key"""
    
    # Generate RSA private key for CA (4096 bits for strong security)
    print("[*] Generating CA private key (4096-bit RSA)...")
    ca_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    
    # Create CA certificate details
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Islamabad"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"FAST-NUCES SecureChat"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"Certificate Authority"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"SecureChat Root CA"),
    ])
    
    # Build the certificate
    print("[*] Building self-signed CA certificate...")
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))  # 10 years
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_private_key.public_key()),
            critical=False,
        )
        .sign(ca_private_key, hashes.SHA256(), default_backend())
    )
    
    # Ensure certs directory exists
    os.makedirs("certs", exist_ok=True)
    
    # Save CA private key
    print("[*] Saving CA private key to certs/ca_key.pem...")
    with open("certs/ca_key.pem", "wb") as f:
        f.write(
            ca_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    
    # Save CA certificate
    print("[*] Saving CA certificate to certs/ca_cert.pem...")
    with open("certs/ca_cert.pem", "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    
    print("\n[✓] Root CA created successfully!")
    print("    - Private Key: certs/ca_key.pem")
    print("    - Certificate: certs/ca_cert.pem")
    print("\n[!] Keep ca_key.pem secret and secure!")
    
    # Display certificate info
    print("\n" + "="*60)
    print("CA Certificate Information:")
    print("="*60)
    print(f"Subject: {ca_cert.subject.rfc4514_string()}")
    print(f"Issuer: {ca_cert.issuer.rfc4514_string()}")
    print(f"Serial Number: {ca_cert.serial_number}")
    print(f"Valid From: {ca_cert.not_valid_before}")
    print(f"Valid Until: {ca_cert.not_valid_after}")
    print("="*60)


if __name__ == "__main__":
    generate_root_ca()