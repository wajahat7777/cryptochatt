"""
Certificate Authority Generator
Creates a self-signed root CA certificate with RSA key pair for PKI infrastructure.
"""

import argparse
from pathlib import Path
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID


def create_rsa_keypair():
    """Generate a new RSA key pair with standard parameters."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )


def build_ca_identity(ca_name: str):
    """Construct X.509 name attributes for the certificate authority."""
    return x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, ca_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat CA"),
    ])


def configure_ca_extensions():
    """Define certificate extensions required for a valid CA."""
    basic_constraints = x509.BasicConstraints(ca=True, path_length=None)
    
    key_usage_flags = x509.KeyUsage(
        key_cert_sign=True,
        crl_sign=True,
        digital_signature=False,
        key_encipherment=False,
        content_commitment=False,
        data_encipherment=False,
        key_agreement=False,
        encipher_only=False,
        decipher_only=False
    )
    
    return [(basic_constraints, True), (key_usage_flags, True)]


def construct_ca_certificate(ca_key, ca_identity, validity_years=10):
    """Build and sign the root CA certificate."""
    current_time = datetime.now(timezone.utc)
    expiration = current_time + timedelta(days=validity_years * 365)
    
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(ca_identity)
    builder = builder.issuer_name(ca_identity)
    builder = builder.public_key(ca_key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(current_time)
    builder = builder.not_valid_after(expiration)
    
    extensions = configure_ca_extensions()
    for ext, is_critical in extensions:
        builder = builder.add_extension(ext, critical=is_critical)
    
    return builder.sign(ca_key, hashes.SHA256())


def persist_key_to_disk(key_obj, file_path: Path):
    """Write private key to file in PEM format."""
    key_data = key_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    file_path.write_bytes(key_data)


def persist_cert_to_disk(cert_obj, file_path: Path):
    """Write certificate to file in PEM format."""
    cert_data = cert_obj.public_bytes(serialization.Encoding.PEM)
    file_path.write_bytes(cert_data)


def create_root_authority(ca_name: str, output_directory: Path = Path("certs")):
    """Main function to generate complete root CA infrastructure."""
    output_directory.mkdir(parents=True, exist_ok=True)
    
    ca_private_key = create_rsa_keypair()
    ca_identity = build_ca_identity(ca_name)
    ca_certificate = construct_ca_certificate(ca_private_key, ca_identity)
    
    key_file = output_directory / "ca.key"
    cert_file = output_directory / "ca.crt"
    
    persist_key_to_disk(ca_private_key, key_file)
    persist_cert_to_disk(ca_certificate, cert_file)
    
    print(f"Root CA generated successfully:")
    print(f"  Private key: {key_file}")
    print(f"  Certificate: {cert_file}")
    print(f"  CA Name: {ca_name}")


def parse_arguments():
    """Handle command-line argument parsing."""
    arg_parser = argparse.ArgumentParser(
        description="Generate Root Certificate Authority"
    )
    arg_parser.add_argument(
        "--name",
        required=True,
        help="Common Name for the CA"
    )
    arg_parser.add_argument(
        "--out",
        default="certs",
        help="Output directory (default: certs)"
    )
    return arg_parser.parse_args()


if __name__ == "__main__":
    parsed_args = parse_arguments()
    create_root_authority(parsed_args.name, Path(parsed_args.out))
