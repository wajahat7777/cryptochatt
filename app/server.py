"""
Secure Chat Server Implementation
Handles secure client connections using application-layer cryptographic protocols.
"""

import os
import json
import socket
import secrets
import tempfile
from pathlib import Path
from dotenv import load_dotenv
from app.common.protocol import (
    Hello, ServerHello, Register, Login, DHClient, DHServer, Msg, Receipt
)
from app.common.utils import now_ms, b64e, b64d, sha256_hex
from app.crypto import pki, aes, sign, dh
from app.storage import db
from app.storage.transcript import TranscriptLogger, get_cert_fingerprint

load_dotenv()


def retrieve_server_certificates():
    """Load server certificate, private key, and CA certificate paths."""
    cert_file = Path(os.getenv('SERVER_CERT_PATH', 'certs/server.crt'))
    key_file = Path(os.getenv('SERVER_KEY_PATH', 'certs/server.key'))
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


def validate_client_certificate(
    connection: socket.socket,
    client_cert_content: str,
    ca_cert_file: Path
) -> bool:
    """Verify client certificate against trusted CA."""
    try:
        pki.validate_certificate(client_cert_content, ca_cert_file)
        return True
    except ValueError as e:
        transmit_json_message(connection, {"error": str(e)})
        return False


def perform_hello_exchange(connection: socket.socket, server_cert: str):
    """Execute certificate exchange with client."""
    client_hello_data = read_json_message(connection)
    client_hello = Hello.model_validate(client_hello_data)
    client_cert_content = client_hello.client_cert
    
    server_random_nonce = secrets.token_bytes(16)
    server_hello = ServerHello(
        server_cert=server_cert,
        nonce=b64e(server_random_nonce)
    )
    transmit_json_message(connection, server_hello.model_dump())
    
    return client_cert_content


def establish_temporary_encryption_key(connection: socket.socket) -> bytes:
    """Perform Diffie-Hellman exchange to derive temporary AES key."""
    server_private = dh.generate_private_key()
    server_public = dh.compute_public_value(dh.DEFAULT_G, dh.DEFAULT_P, server_private)
    
    client_dh_data = read_json_message(connection)
    client_dh = DHClient.model_validate(client_dh_data)
    
    shared_secret = dh.compute_shared_secret(
        client_dh.A, server_private, client_dh.p
    )
    temp_key = dh.derive_key(shared_secret)
    
    server_dh_response = DHServer(B=server_public)
    transmit_json_message(connection, server_dh_response.model_dump())
    
    return temp_key


def handle_salt_request(connection: socket.socket, email_address: str):
    """Process client request for user salt."""
    salt_value = db.get_user_salt(email_address)
    if salt_value:
        transmit_json_message(connection, {"salt": b64e(salt_value)})
        return True
    else:
        transmit_json_message(connection, {"error": "User not found"})
        return False


def decrypt_authentication_payload(encrypted_data: str, decryption_key: bytes) -> dict:
    """Decrypt and parse authentication message."""
    try:
        decrypted_bytes = aes.decrypt(encrypted_data, decryption_key)
        return json.loads(decrypted_bytes.decode('utf-8'))
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}")


def process_registration_request(connection: socket.socket, auth_payload: dict):
    """Handle new user registration."""
    import pymysql
    
    user_email = auth_payload['email']
    user_name = auth_payload['username']
    password_hash = auth_payload['pwd']
    salt_bytes = b64d(auth_payload['salt'])
    
    database_connection = db.get_db_connection()
    try:
        with database_connection.cursor() as cursor:
            cursor.execute("SELECT username FROM users WHERE username = %s", (user_name,))
            if cursor.fetchone():
                raise ValueError(f"Username '{user_name}' already exists")
            
            cursor.execute("SELECT email FROM users WHERE email = %s", (user_email,))
            if cursor.fetchone():
                raise ValueError(f"Email '{user_email}' already registered")
            
            cursor.execute(
                "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
                (user_email, user_name, salt_bytes, password_hash)
            )
        database_connection.commit()
        transmit_json_message(connection, {"status": "registered"})
    except Exception as e:
        database_connection.rollback()
        transmit_json_message(connection, {"error": str(e)})
        raise
    finally:
        database_connection.close()


def process_login_request(connection: socket.socket, auth_payload: dict):
    """Handle user authentication."""
    user_email = auth_payload['email']
    password_hash = auth_payload['pwd']
    
    salt_value = db.get_user_salt(user_email)
    if not salt_value:
        transmit_json_message(connection, {"error": "Invalid credentials"})
        return False
    
    if db.verify_login(user_email, password_hash, salt_value):
        transmit_json_message(connection, {"status": "logged_in"})
        return True
    else:
        transmit_json_message(connection, {"error": "Invalid credentials"})
        return False


def handle_authentication_flow(connection: socket.socket, encryption_key: bytes) -> bool:
    """Process authentication request (registration or login)."""
    initial_request = read_json_message(connection)
    
    if initial_request.get('type') == 'get_salt':
        email = initial_request.get('email')
        if not email:
            transmit_json_message(connection, {"error": "Missing email"})
            return False
        
        if not handle_salt_request(connection, email):
            return False
        
        encrypted_auth = read_json_message(connection)
    else:
        encrypted_auth = initial_request
    
    encrypted_payload = encrypted_auth.get('payload', '')
    if not encrypted_payload:
        transmit_json_message(connection, {"error": "Missing encrypted payload"})
        return False
    
    try:
        auth_data = decrypt_authentication_payload(encrypted_payload, encryption_key)
    except ValueError as e:
        transmit_json_message(connection, {"error": str(e)})
        return False
    
    auth_type = auth_data.get('type')
    if auth_type == 'register':
        try:
            process_registration_request(connection, auth_data)
            return True
        except ValueError:
            return False
    elif auth_type == 'login':
        return process_login_request(connection, auth_data)
    else:
        transmit_json_message(connection, {"error": "Invalid message type"})
        return False


def establish_session_encryption_key(connection: socket.socket) -> bytes:
    """Perform Diffie-Hellman exchange to derive session key."""
    client_dh_data = read_json_message(connection)
    client_dh = DHClient.model_validate(client_dh_data)
    
    server_private_key = dh.generate_private_key()
    server_public_value = dh.compute_public_value(
        client_dh.g, client_dh.p, server_private_key
    )
    
    shared_secret = dh.compute_shared_secret(
        client_dh.A, server_private_key, client_dh.p
    )
    session_key = dh.derive_key(shared_secret)
    
    server_dh_response = DHServer(B=server_public_value)
    transmit_json_message(connection, server_dh_response.model_dump())
    
    return session_key


def verify_message_signature(
    message_obj: Msg,
    client_cert_content: str
) -> bool:
    """Validate message signature using client certificate."""
    seq_bytes = message_obj.seqno.to_bytes(8, byteorder='big')
    time_bytes = message_obj.ts.to_bytes(8, byteorder='big')
    ct_bytes = message_obj.ct.encode('utf-8')
    digest = seq_bytes + time_bytes + ct_bytes
    
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.crt', delete=False) as tmp_file:
            tmp_file.write(client_cert_content)
            temp_cert_path = Path(tmp_file.name)
        
        try:
            sign.verify(digest, message_obj.sig, temp_cert_path)
            return True
        finally:
            temp_cert_path.unlink()
    except ValueError:
        return False


def process_incoming_message(
    connection: socket.socket,
    message_obj: Msg,
    session_key: bytes,
    client_cert: str,
    transcript_log: TranscriptLogger,
    client_fingerprint: str
) -> bool:
    """Handle a single incoming message: verify, decrypt, and log."""
    if not verify_message_signature(message_obj, client_cert):
        transmit_json_message(connection, {"error": "SIG_FAIL: Signature verification failed"})
        return False
    
    try:
        decrypted_text = aes.decrypt(message_obj.ct, session_key)
        print(f"Received: {decrypted_text.decode('utf-8', errors='ignore')}")
    except Exception as e:
        transmit_json_message(connection, {"error": f"Decryption failed: {e}"})
        return False
    
    transcript_log.append(
        message_obj.seqno, message_obj.ts, message_obj.ct,
        message_obj.sig, client_fingerprint
    )
    
    transmit_json_message(connection, {"status": "received", "seqno": message_obj.seqno})
    return True


def handle_message_loop(
    connection: socket.socket,
    session_key: bytes,
    client_cert: str,
    transcript_log: TranscriptLogger,
    client_fingerprint: str
):
    """Process incoming messages until receipt is received."""
    print("Session established. Waiting for messages...")
    last_sequence = 0
    
    while True:
        incoming_data = read_json_message(connection)
        
        if incoming_data.get('type') == 'receipt':
            break
        
        message = Msg.model_validate(incoming_data)
        
        if message.seqno <= last_sequence:
            transmit_json_message(
                connection,
                {"error": "REPLAY: Sequence number must be strictly increasing"}
            )
            continue
        
        last_sequence = message.seqno
        
        process_incoming_message(
            connection, message, session_key, client_cert,
            transcript_log, client_fingerprint
        )


def generate_server_receipt(
    transcript_log: TranscriptLogger,
    signing_key: Path
) -> Receipt:
    """Create and sign server session receipt."""
    transcript_hash = transcript_log.compute_hash()
    first_seq = transcript_log.get_first_seq() or 0
    last_seq = transcript_log.get_last_seq() or 0
    
    receipt_signature = sign.sign(
        transcript_hash.encode('utf-8'),
        signing_key
    )
    
    return Receipt(
        peer="server",
        first_seq=first_seq,
        last_seq=last_seq,
        transcript_sha256=transcript_hash,
        sig=receipt_signature
    )


def save_receipt_file(receipt_obj: Receipt, file_path: Path):
    """Write receipt to JSON file."""
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, 'w') as f:
        json.dump(receipt_obj.model_dump(), f, indent=2)


def finalize_session(
    connection: socket.socket,
    transcript_log: TranscriptLogger,
    server_receipt: Receipt,
    client_address: tuple
):
    """Complete session and save all artifacts."""
    transmit_json_message(connection, server_receipt.model_dump())
    
    receipt_file = Path(f"transcripts/server_receipt_{client_address[0]}_{client_address[1]}.json")
    save_receipt_file(server_receipt, receipt_file)
    print(f"Server receipt saved to: {receipt_file}")
    
    export_path = transcript_log.export()
    print(f"Transcript exported to: {export_path}")
    print(f"Session completed. All files saved in transcripts/ directory.")


def handle_client_session(client_connection: socket.socket, client_address: tuple):
    """Process complete client session from connection to disconnection."""
    print(f"Client connected from {client_address}")
    session_encryption_key = None
    last_sequence_number = 0
    client_certificate_content = None
    
    try:
        server_cert, server_key_file, ca_cert_file = retrieve_server_certificates()
        
        client_certificate_content = perform_hello_exchange(client_connection, server_cert)
        
        if not validate_client_certificate(client_connection, client_certificate_content, ca_cert_file):
            return
        
        temp_encryption_key = establish_temporary_encryption_key(client_connection)
        
        if not handle_authentication_flow(client_connection, temp_encryption_key):
            return
        
        session_encryption_key = establish_session_encryption_key(client_connection)
        
        transcript_file = Path(f"transcripts/server_{client_address[0]}_{client_address[1]}.txt")
        transcript_logger = TranscriptLogger(transcript_file)
        client_cert_fingerprint = get_cert_fingerprint(client_certificate_content)
        
        handle_message_loop(
            client_connection, session_encryption_key, client_certificate_content,
            transcript_logger, client_cert_fingerprint
        )
        
        server_receipt = generate_server_receipt(transcript_logger, server_key_file)
        
        finalize_session(
            client_connection, transcript_logger, server_receipt, client_address
        )
        
    except Exception as e:
        print(f"Error handling client: {e}")
        try:
            transmit_json_message(client_connection, {"error": str(e)})
        except:
            pass
    finally:
        client_connection.close()
        print(f"Client {client_address} disconnected")


def start_server():
    """Main server application entry point."""
    server_host = os.getenv('SERVER_HOST', 'localhost')
    server_port = int(os.getenv('SERVER_PORT', 8888))
    
    listening_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listening_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listening_socket.bind((server_host, server_port))
    listening_socket.listen(5)
    
    print(f"Server listening on {server_host}:{server_port}")
    
    try:
        while True:
            client_socket, client_address = listening_socket.accept()
            handle_client_session(client_socket, client_address)
    except KeyboardInterrupt:
        print("\nServer shutting down...")
    finally:
        listening_socket.close()


if __name__ == "__main__":
    start_server()
