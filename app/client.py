"""
Secure Chat Client Implementation
Establishes secure communication channel using application-layer cryptography.
"""

import os
import json
import socket
import secrets
import hashlib
from pathlib import Path
from dotenv import load_dotenv
from app.common.protocol import (
    Hello, ServerHello, Register, Login, DHClient, DHServer, Msg, Receipt
)
from app.common.utils import now_ms, b64e, b64d, sha256_hex
from app.crypto import pki, aes, sign, dh
from app.storage.transcript import TranscriptLogger, get_cert_fingerprint

load_dotenv()


def retrieve_certificate_files():
    """Load client certificate, private key, and CA certificate paths from environment."""
    cert_file = Path(os.getenv('CLIENT_CERT_PATH', 'certs/client.crt'))
    key_file = Path(os.getenv('CLIENT_KEY_PATH', 'certs/client.key'))
    ca_file = Path(os.getenv('CA_CERT_PATH', 'certs/ca.crt'))
    
    cert_content = cert_file.read_text()
    
    return cert_content, key_file, ca_file


def transmit_json_message(connection: socket.socket, payload: dict):
    """Serialize and send JSON message over TCP socket."""
    serialized = json.dumps(payload).encode('utf-8')
    connection.sendall(serialized + b'\n')


def read_json_message(connection: socket.socket) -> dict:
    """Receive and deserialize JSON message from TCP socket."""
    data_buffer = b''
    while b'\n' not in data_buffer:
        received_chunk = connection.recv(4096)
        if not received_chunk:
            raise ConnectionError("Connection closed")
        data_buffer += received_chunk
    message_line = data_buffer.split(b'\n', 1)[0]
    return json.loads(message_line.decode('utf-8'))


def perform_hello_exchange(connection: socket.socket, client_cert: str, ca_file: Path):
    """Execute certificate exchange and validation with server."""
    random_nonce = secrets.token_bytes(16)
    client_hello = Hello(
        client_cert=client_cert,
        nonce=b64e(random_nonce)
    )
    transmit_json_message(connection, client_hello.model_dump())
    
    server_response = read_json_message(connection)
    if 'error' in server_response:
        print(f"Error: {server_response['error']}")
        return None
    
    server_hello = ServerHello.model_validate(server_response)
    
    try:
        pki.validate_certificate(server_hello.server_cert, ca_file, expected_cn="server.local")
        print("Server certificate validated")
        return server_hello
    except ValueError as e:
        print(f"Certificate validation failed: {e}")
        return None


def establish_temporary_encryption_key(connection: socket.socket):
    """Perform Diffie-Hellman exchange to derive temporary AES key for authentication."""
    private_exponent = dh.generate_private_key()
    public_value = dh.compute_public_value(dh.DEFAULT_G, dh.DEFAULT_P, private_exponent)
    
    dh_params = DHClient(
        g=dh.DEFAULT_G,
        p=dh.DEFAULT_P,
        A=public_value
    )
    transmit_json_message(connection, dh_params.model_dump())
    
    server_dh_response = read_json_message(connection)
    server_dh = DHServer.model_validate(server_dh_response)
    
    shared_secret = dh.compute_shared_secret(
        server_dh.B, private_exponent, dh.DEFAULT_P
    )
    return dh.derive_key(shared_secret)


def create_password_hash(salt_bytes: bytes, password_text: str) -> str:
    """Compute SHA-256 hash of salted password."""
    combined = salt_bytes + password_text.encode('utf-8')
    return hashlib.sha256(combined).hexdigest()


def process_user_registration(connection: socket.socket, encryption_key: bytes):
    """Handle new user registration flow."""
    user_email = input("Email: ").strip()
    user_name = input("Username: ").strip()
    user_password = input("Password: ").strip()
    
    salt_value = secrets.token_bytes(16)
    password_hash = create_password_hash(salt_value, user_password)
    
    registration_payload = {
        'type': 'register',
        'email': user_email,
        'username': user_name,
        'pwd': password_hash,
        'salt': b64e(salt_value)
    }
    
    encrypted_data = aes.encrypt(
        json.dumps(registration_payload).encode('utf-8'),
        encryption_key
    )
    
    transmit_json_message(connection, {'payload': encrypted_data})
    
    registration_response = read_json_message(connection)
    if 'error' in registration_response:
        print(f"Registration failed: {registration_response['error']}")
        return False
    print("Registration successful!")
    return True


def retrieve_user_salt(connection: socket.socket, email_address: str) -> bytes:
    """Request and receive salt for user authentication."""
    transmit_json_message(connection, {'type': 'get_salt', 'email': email_address})
    salt_response = read_json_message(connection)
    
    if 'error' in salt_response or 'salt' not in salt_response:
        raise ValueError("Failed to get salt")
    
    return b64d(salt_response['salt'])


def process_user_login(connection: socket.socket, encryption_key: bytes):
    """Handle user authentication flow."""
    user_email = input("Email: ").strip()
    user_password = input("Password: ").strip()
    
    try:
        salt_bytes = retrieve_user_salt(connection, user_email)
    except ValueError as e:
        print(str(e))
        return False
    
    password_hash = create_password_hash(salt_bytes, user_password)
    
    login_payload = {
        'type': 'login',
        'email': user_email,
        'pwd': password_hash,
        'nonce': b64e(secrets.token_bytes(16))
    }
    
    encrypted_data = aes.encrypt(
        json.dumps(login_payload).encode('utf-8'),
        encryption_key
    )
    
    transmit_json_message(connection, {'payload': encrypted_data})
    
    login_response = read_json_message(connection)
    if 'error' in login_response:
        print(f"Login failed: {login_response['error']}")
        return False
    print("Login successful!")
    return True


def handle_authentication(connection: socket.socket, encryption_key: bytes) -> bool:
    """Process user registration or login based on user choice."""
    print("\n1. Register")
    print("2. Login")
    user_choice = input("Choose (1/2): ").strip()
    
    if user_choice == '1':
        return process_user_registration(connection, encryption_key)
    elif user_choice == '2':
        return process_user_login(connection, encryption_key)
    else:
        print("Invalid choice")
        return False


def establish_session_key(connection: socket.socket) -> bytes:
    """Perform Diffie-Hellman exchange to derive session encryption key."""
    session_private = dh.generate_private_key()
    session_public = dh.compute_public_value(dh.DEFAULT_G, dh.DEFAULT_P, session_private)
    
    session_dh_params = DHClient(
        g=dh.DEFAULT_G,
        p=dh.DEFAULT_P,
        A=session_public
    )
    transmit_json_message(connection, session_dh_params.model_dump())
    
    server_session_response = read_json_message(connection)
    server_session_dh = DHServer.model_validate(server_session_response)
    
    session_shared = dh.compute_shared_secret(
        server_session_dh.B, session_private, dh.DEFAULT_P
    )
    return dh.derive_key(session_shared)


def prepare_message_signature(sequence_num: int, timestamp: int, ciphertext: str) -> bytes:
    """Construct digest data for message signing."""
    seq_bytes = sequence_num.to_bytes(8, byteorder='big')
    time_bytes = timestamp.to_bytes(8, byteorder='big')
    ct_bytes = ciphertext.encode('utf-8')
    return seq_bytes + time_bytes + ct_bytes


def send_encrypted_message(
    connection: socket.socket,
    message_text: str,
    sequence_number: int,
    encryption_key: bytes,
    signing_key_path: Path
) -> tuple:
    """Encrypt, sign, and transmit a chat message."""
    encrypted_content = aes.encrypt(message_text.encode('utf-8'), encryption_key)
    current_timestamp = now_ms()
    
    signature_data = prepare_message_signature(sequence_number, current_timestamp, encrypted_content)
    message_signature = sign.sign(signature_data, signing_key_path)
    
    message_obj = Msg(
        seqno=sequence_number,
        ts=current_timestamp,
        ct=encrypted_content,
        sig=message_signature
    )
    transmit_json_message(connection, message_obj.model_dump())
    
    return encrypted_content, current_timestamp, message_signature


def process_message_exchange(
    connection: socket.socket,
    session_key: bytes,
    signing_key: Path,
    transcript_log: TranscriptLogger,
    server_fingerprint: str
):
    """Handle interactive message sending loop."""
    print("\nSession established! Type messages (or 'quit' to exit):")
    
    current_sequence = 1
    
    while True:
        user_input = input("> ").strip()
        if user_input.lower() == 'quit':
            break
        
        ciphertext, timestamp, signature = send_encrypted_message(
            connection, user_input, current_sequence, session_key, signing_key
        )
        
        transcript_log.append(
            current_sequence, timestamp, ciphertext, signature, server_fingerprint
        )
        
        server_response = read_json_message(connection)
        if 'error' in server_response:
            print(f"Error: {server_response['error']}")
            if 'REPLAY' in server_response['error']:
                break
        else:
            print(f"Server acknowledged: {server_response.get('status', 'OK')}")
        
        current_sequence += 1
    
    return current_sequence - 1


def generate_session_receipt(
    transcript_log: TranscriptLogger,
    last_sequence: int,
    signing_key: Path
) -> Receipt:
    """Create and sign session receipt for non-repudiation."""
    transcript_hash_value = transcript_log.compute_hash()
    first_sequence = transcript_log.get_first_seq() or 1
    final_sequence = transcript_log.get_last_seq() or last_sequence
    
    receipt_signature = sign.sign(
        transcript_hash_value.encode('utf-8'),
        signing_key
    )
    
    return Receipt(
        peer="client",
        first_seq=first_sequence,
        last_seq=final_sequence,
        transcript_sha256=transcript_hash_value,
        sig=receipt_signature
    )


def save_receipt_to_file(receipt_obj: Receipt, file_path: Path):
    """Persist receipt to JSON file."""
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, 'w') as f:
        json.dump(receipt_obj.model_dump(), f, indent=2)


def handle_receipt_exchange(
    connection: socket.socket,
    client_receipt: Receipt,
    server_host: str,
    server_port: int
):
    """Exchange and save session receipts."""
    transmit_json_message(connection, client_receipt.model_dump())
    
    server_receipt_data = read_json_message(connection)
    if 'type' in server_receipt_data and server_receipt_data['type'] == 'receipt':
        server_receipt = Receipt.model_validate(server_receipt_data)
        print(f"\nServer receipt received:")
        print(f"  First seq: {server_receipt.first_seq}")
        print(f"  Last seq: {server_receipt.last_seq}")
        print(f"  Transcript hash: {server_receipt.transcript_sha256}")
        
        server_receipt_file = Path(f"transcripts/server_receipt_{server_host}_{server_port}.json")
        save_receipt_to_file(server_receipt, server_receipt_file)
        print(f"  Server receipt saved to: {server_receipt_file}")


def complete_session(
    connection: socket.socket,
    transcript_log: TranscriptLogger,
    client_receipt: Receipt,
    server_host: str,
    server_port: int
):
    """Finalize session and save all artifacts."""
    handle_receipt_exchange(connection, client_receipt, server_host, server_port)
    
    client_receipt_file = Path(f"transcripts/client_receipt_{server_host}_{server_port}.json")
    save_receipt_to_file(client_receipt, client_receipt_file)
    print(f"\nClient receipt saved to: {client_receipt_file}")
    
    export_path = transcript_log.export()
    print(f"Transcript exported to: {export_path}")
    print(f"\nSession completed. All files saved in transcripts/ directory.")


def run_client():
    """Main client application entry point."""
    server_host = os.getenv('SERVER_HOST', 'localhost')
    server_port = int(os.getenv('SERVER_PORT', 8888))
    
    client_cert, client_key_file, ca_cert_file = retrieve_certificate_files()
    
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((server_host, server_port))
        print(f"Connected to server at {server_host}:{server_port}")
        
        server_hello = perform_hello_exchange(client_socket, client_cert, ca_cert_file)
        if not server_hello:
            return
        
        temp_key = establish_temporary_encryption_key(client_socket)
        
        auth_success = handle_authentication(client_socket, temp_key)
        if not auth_success:
            return
        
        session_encryption_key = establish_session_key(client_socket)
        
        transcript_file = Path(f"transcripts/client_{server_host}_{server_port}.txt")
        transcript_logger = TranscriptLogger(transcript_file)
        server_cert_fp = get_cert_fingerprint(server_hello.server_cert)
        
        last_seq_num = process_message_exchange(
            client_socket, session_encryption_key, client_key_file,
            transcript_logger, server_cert_fp
        )
        
        client_receipt = generate_session_receipt(
            transcript_logger, last_seq_num, client_key_file
        )
        
        complete_session(
            client_socket, transcript_logger, client_receipt,
            server_host, server_port
        )
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()


if __name__ == "__main__":
    run_client()
