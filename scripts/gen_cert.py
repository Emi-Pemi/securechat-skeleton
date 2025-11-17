#!/usr/bin/env python3
"""
Generate server and client certificates signed by the Root CA
"""

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import datetime
import sys


def load_ca():
    """Load CA private key and certificate"""
    with open("certs/ca_key.pem", "rb") as f:
        ca_private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    
    with open("certs/ca_cert.pem", "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    
    return ca_private_key, ca_cert


def generate_certificate(entity_type, common_name, dns_names=None):
    """
    Generate a certificate signed by the CA
    
    Args:
        entity_type: 'server' or 'client'
        common_name: CN for the certificate
        dns_names: list of DNS names for SAN (Subject Alternative Name)
    """
    
    # Load CA
    print(f"[*] Loading CA credentials...")
    ca_private_key, ca_cert = load_ca()
    
    # Generate private key for this entity
    print(f"[*] Generating {entity_type} private key (2048-bit RSA)...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Create subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Islamabad"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"FAST-NUCES SecureChat"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, entity_type.capitalize()),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    # Build certificate
    print(f"[*] Building {entity_type} certificate...")
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))  # 1 year
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_private_key.public_key()),
            critical=False,
        )
    )
    
    # Add appropriate key usage
    if entity_type == "server":
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            ]),
            critical=True,
        )
        
        # Add Subject Alternative Names for server
        if dns_names:
            san_list = [x509.DNSName(name) for name in dns_names]
            builder = builder.add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False,
            )
    
    elif entity_type == "client":
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=True,  # For non-repudiation
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=True,
        )
    
    # Sign the certificate with CA
    cert = builder.sign(ca_private_key, hashes.SHA256(), default_backend())
    
    # Save private key
    key_filename = f"certs/{entity_type}_key.pem"
    print(f"[*] Saving {entity_type} private key to {key_filename}...")
    with open(key_filename, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    
    # Save certificate
    cert_filename = f"certs/{entity_type}_cert.pem"
    print(f"[*] Saving {entity_type} certificate to {cert_filename}...")
    with open(cert_filename, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print(f"\n[✓] {entity_type.capitalize()} certificate created successfully!")
    print(f"    - Private Key: {key_filename}")
    print(f"    - Certificate: {cert_filename}")
    
    # Display certificate info
    print("\n" + "="*60)
    print(f"{entity_type.capitalize()} Certificate Information:")
    print("="*60)
    print(f"Subject: {cert.subject.rfc4514_string()}")
    print(f"Issuer: {cert.issuer.rfc4514_string()}")
    print(f"Serial Number: {cert.serial_number}")
    print(f"Valid From: {cert.not_valid_before}")
    print(f"Valid Until: {cert.not_valid_after}")
    print("="*60 + "\n")


def main():
    if len(sys.argv) < 3:
        print("Usage: python gen_cert.py <server|client> <common_name> [dns_names...]")
        print("\nExamples:")
        print("  python gen_cert.py server localhost localhost 127.0.0.1")
        print("  python gen_cert.py client client1")
        sys.exit(1)
    
    entity_type = sys.argv[1].lower()
    common_name = sys.argv[2]
    dns_names = sys.argv[3:] if len(sys.argv) > 3 else None
    
    if entity_type not in ["server", "client"]:
        print("[!] Error: entity_type must be 'server' or 'client'")
        sys.exit(1)
    
    generate_certificate(entity_type, common_name, dns_names)


if __name__ == "__main__":
    main()