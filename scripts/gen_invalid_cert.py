"""
Untrusted Certificate Generator
Creates self-signed certificates for security testing purposes.
These certificates should be rejected by the PKI validation system.
"""

import argparse
from pathlib import Path
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID


def create_test_keypair():
    """Generate an RSA key pair for the untrusted certificate."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )


def build_self_signed_identity(cn_value: str):
    """Create X.509 name where subject equals issuer (self-signed)."""
    name_attributes = [
        x509.NameAttribute(NameOID.COMMON_NAME, cn_value),
    ]
    return x509.Name(name_attributes)


def calculate_expiration_date(start_date, lifetime_days=365):
    """Determine certificate expiration from start date."""
    return start_date + timedelta(days=lifetime_days)


def assemble_self_signed_certificate(key_obj, subject_issuer_name):
    """Construct a certificate that signs itself (untrusted)."""
    now = datetime.now(timezone.utc)
    expires = calculate_expiration_date(now)
    
    certificate = x509.CertificateBuilder()
    certificate = certificate.subject_name(subject_issuer_name)
    certificate = certificate.issuer_name(subject_issuer_name)
    certificate = certificate.public_key(key_obj.public_key())
    certificate = certificate.serial_number(x509.random_serial_number())
    certificate = certificate.not_valid_before(now)
    certificate = certificate.not_valid_after(expires)
    
    return certificate.sign(key_obj, hashes.SHA256())


def export_private_key(key_obj, target_path: Path):
    """Write private key to specified file location."""
    key_serialized = key_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    target_path.write_bytes(key_serialized)


def export_certificate(cert_obj, target_path: Path):
    """Write certificate to specified file location."""
    cert_serialized = cert_obj.public_bytes(serialization.Encoding.PEM)
    target_path.write_bytes(cert_serialized)


def create_untrusted_certificate(cn_name: str, output_folder: Path = Path("certs")):
    """Generate a self-signed certificate that will fail CA validation."""
    output_folder.mkdir(parents=True, exist_ok=True)
    
    test_key = create_test_keypair()
    identity = build_self_signed_identity(cn_name)
    untrusted_cert = assemble_self_signed_certificate(test_key, identity)
    
    key_output = output_folder / "invalid.key"
    cert_output = output_folder / "invalid.crt"
    
    export_private_key(test_key, key_output)
    export_certificate(untrusted_cert, cert_output)
    
    print(f"Invalid self-signed certificate generated:")
    print(f"  Private key: {key_output}")
    print(f"  Certificate: {cert_output}")
    print(f"  Note: This certificate is NOT signed by your CA and should be rejected")


def configure_cli():
    """Set up command-line argument handling."""
    parser = argparse.ArgumentParser(
        description="Generate invalid certificate for testing"
    )
    parser.add_argument(
        "--name",
        default="invalid.local",
        help="Common Name for invalid cert"
    )
    parser.add_argument(
        "--out",
        default="certs",
        help="Output directory"
    )
    return parser


if __name__ == "__main__":
    cli_parser = configure_cli()
    cli_args = cli_parser.parse_args()
    
    create_untrusted_certificate(cli_args.name, Path(cli_args.out))

