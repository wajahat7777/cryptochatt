"""
Certificate Issuance Script
Generates X.509 certificates for clients/servers signed by the root CA.
"""

import argparse
from pathlib import Path
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID


def load_ca_credentials(cert_file: Path, key_file: Path):
    """Read CA certificate and signing key from disk."""
    ca_cert_data = cert_file.read_bytes()
    ca_key_data = key_file.read_bytes()
    
    ca_certificate = x509.load_pem_x509_certificate(ca_cert_data)
    ca_signing_key = serialization.load_pem_private_key(ca_key_data, password=None)
    
    return ca_certificate, ca_signing_key


def generate_entity_keypair():
    """Create a new RSA key pair for the certificate subject."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )


def create_subject_name(common_name: str):
    """Build X.509 subject name from common name."""
    return x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])


def get_validity_period(duration_days=365):
    """Calculate certificate validity time window."""
    start_time = datetime.now(timezone.utc)
    end_time = start_time + timedelta(days=duration_days)
    return start_time, end_time


def add_subject_alternative_name(builder, dns_name: str):
    """Include SAN extension with DNS name."""
    san_extension = x509.SubjectAlternativeName([
        x509.DNSName(dns_name)
    ])
    return builder.add_extension(san_extension, critical=False)


def add_key_usage_restrictions(builder):
    """Configure allowed key operations."""
    usage = x509.KeyUsage(
        digital_signature=True,
        key_encipherment=True,
        key_cert_sign=False,
        crl_sign=False,
        content_commitment=False,
        data_encipherment=False,
        key_agreement=False,
        encipher_only=False,
        decipher_only=False
    )
    return builder.add_extension(usage, critical=True)


def add_extended_key_usage(builder):
    """Specify extended purposes for the certificate."""
    extended_usage = x509.ExtendedKeyUsage([
        ExtendedKeyUsageOID.SERVER_AUTH,
        ExtendedKeyUsageOID.CLIENT_AUTH
    ])
    return builder.add_extension(extended_usage, critical=False)


def build_certificate(
    subject_name,
    issuer_name,
    public_key,
    validity_start,
    validity_end,
    dns_name: str
):
    """Construct certificate with all required extensions."""
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject_name)
    builder = builder.issuer_name(issuer_name)
    builder = builder.public_key(public_key)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(validity_start)
    builder = builder.not_valid_after(validity_end)
    builder = add_subject_alternative_name(builder, dns_name)
    builder = add_key_usage_restrictions(builder)
    builder = add_extended_key_usage(builder)
    
    return builder


def extract_ca_name(ca_certificate):
    """Retrieve CA common name from certificate."""
    cn_attributes = ca_certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return cn_attributes[0].value if cn_attributes else "Unknown"


def write_key_file(key_obj, destination: Path):
    """Save private key to filesystem."""
    key_bytes = key_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    destination.write_bytes(key_bytes)


def write_cert_file(cert_obj, destination: Path):
    """Save certificate to filesystem."""
    cert_bytes = cert_obj.public_bytes(serialization.Encoding.PEM)
    destination.write_bytes(cert_bytes)


def determine_output_prefix(cn_value: str, user_specified: str = None):
    """Determine the output filename prefix."""
    if user_specified:
        return Path(user_specified).stem
    return cn_value.split('.')[0]


def issue_new_certificate(
    common_name: str,
    file_prefix: str,
    ca_cert_file: Path,
    ca_key_file: Path,
    output_directory: Path = Path("certs")
):
    """Main function to create and sign a new certificate."""
    output_directory.mkdir(parents=True, exist_ok=True)
    
    ca_cert, ca_key = load_ca_credentials(ca_cert_file, ca_key_file)
    entity_key = generate_entity_keypair()
    subject = create_subject_name(common_name)
    valid_from, valid_until = get_validity_period()
    
    cert_builder = build_certificate(
        subject,
        ca_cert.subject,
        entity_key.public_key(),
        valid_from,
        valid_until,
        common_name
    )
    
    signed_cert = cert_builder.sign(ca_key, hashes.SHA256())
    
    key_file_path = output_directory / f"{file_prefix}.key"
    cert_file_path = output_directory / f"{file_prefix}.crt"
    
    write_key_file(entity_key, key_file_path)
    write_cert_file(signed_cert, cert_file_path)
    
    ca_name = extract_ca_name(ca_cert)
    
    print(f"Certificate issued successfully:")
    print(f"  Common Name: {common_name}")
    print(f"  Private key: {key_file_path}")
    print(f"  Certificate: {cert_file_path}")
    print(f"  Signed by: {ca_name}")


def setup_argument_parser():
    """Configure command-line interface."""
    parser = argparse.ArgumentParser(
        description="Issue certificate signed by Root CA"
    )
    parser.add_argument(
        "--cn",
        required=True,
        help="Common Name (hostname) for the certificate"
    )
    parser.add_argument(
        "--out",
        help="Output file prefix (default: CN)"
    )
    parser.add_argument(
        "--ca-cert",
        default="certs/ca.crt",
        help="Path to CA certificate"
    )
    parser.add_argument(
        "--ca-key",
        default="certs/ca.key",
        help="Path to CA private key"
    )
    parser.add_argument(
        "--dir",
        default="certs",
        help="Output directory (default: certs)"
    )
    return parser


if __name__ == "__main__":
    arg_parser = setup_argument_parser()
    arguments = arg_parser.parse_args()
    
    prefix = determine_output_prefix(arguments.cn, arguments.out)
    
    issue_new_certificate(
        common_name=arguments.cn,
        file_prefix=prefix,
        ca_cert_file=Path(arguments.ca_cert),
        ca_key_file=Path(arguments.ca_key),
        output_directory=Path(arguments.dir)
    )
