#"""Server skeleton — plain TCP; no TLS. See assignment spec."""

#def main():
#    raise NotImplementedError("students: implement server workflow")

#if __name__ == "__main__":
 #   main()

"""
Secure Chat Server
Handles client connections, authentication, and encrypted messaging
"""

import socket
import json
import threading
import os
from dotenv import load_dotenv

from app.common.protocol import (
    HelloMessage, ServerHelloMessage, DHClientMessage, DHServerMessage,
    RegisterMessage, LoginMessage, AuthResponseMessage, ChatMessage,
    SessionReceipt, ErrorMessage
)
from app.common.utils import now_ms, b64e, b64d, sha256_hex
from app.crypto.aes import aes_encrypt, aes_decrypt
from app.crypto.dh import DHKeyExchange, derive_aes_key
from app.crypto.pki import (
    load_certificate_from_file, load_private_key_from_file,
    validate_certificate, get_certificate_fingerprint, cert_to_pem_string
)
from app.crypto.sign import sign_data, verify_signature, compute_message_digest
from app.storage.db import UserDatabase, hash_password, generate_salt
from app.storage.transcript import TranscriptManager

load_dotenv()


class SecureChatServer:
    """Secure Chat Server handling multiple clients"""
    
    def __init__(self, host='localhost', port=5000):
        self.host = host
        self.port = port
        self.server_socket = None
        
        # Load server certificate and private key
        self.server_cert = load_certificate_from_file('certs/server_cert.pem')
        self.server_key = load_private_key_from_file('certs/server_key.pem')
        
        # Load CA certificate for validation
        self.ca_cert = load_certificate_from_file('certs/ca_cert.pem')
        
        # Database connection
        self.db = UserDatabase()
        
        print(f"[+] Server initialized on {host}:{port}")
        print(f"[+] Server Certificate CN: {self.server_cert.subject.rfc4514_string()}")
    
    def start(self):
        """Start the server and listen for connections"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        
        print(f"\n[*] Server listening on {self.host}:{self.port}")
        print("[*] Waiting for client connections...\n")
        
        try:
            while True:
                client_socket, address = self.server_socket.accept()
                print(f"\n[+] New connection from {address}")
                
                # Handle each client in a separate thread
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address)
                )
                client_thread.daemon = True
                client_thread.start()
                
        except KeyboardInterrupt:
            print("\n[!] Server shutting down...")
        finally:
            self.cleanup()
    
    def handle_client(self, client_socket, address):
        """Handle individual client connection"""
        session_key = None
        temp_key = None
        client_cert = None
        username = None
        transcript = None
        last_seqno = 0
        
        try:
            # Phase 1: Control Plane - Certificate Exchange
            print(f"\n{'='*60}")
            print(f"PHASE 1: CONTROL PLANE - Certificate Exchange")
            print(f"{'='*60}")
            
            # Receive client hello
            data = client_socket.recv(8192).decode('utf-8')
            hello_msg = HelloMessage(**json.loads(data))
            print(f"[<] Received HELLO from client")
            
            # Load and validate client certificate
            client_cert = self.load_cert_from_pem(hello_msg.client_cert)
            is_valid, msg = validate_certificate(client_cert, self.ca_cert)
            
            if not is_valid:
                print(f"[!] Certificate validation failed: {msg}")
                error = ErrorMessage(code="BAD_CERT", message=msg)
                client_socket.send(json.dumps(error.dict()).encode('utf-8'))
                return
            
            print(f"[✓] Client certificate validated successfully")
            client_fingerprint = get_certificate_fingerprint(client_cert)
            print(f"    Client fingerprint: {client_fingerprint[:16]}...")
            
            # Send server hello
            server_hello = ServerHelloMessage(
                server_cert=cert_to_pem_string(self.server_cert),
                nonce=b64e(os.urandom(16))
            )
            client_socket.send(json.dumps(server_hello.dict()).encode('utf-8'))
            print(f"[>] Sent SERVER_HELLO")
            
            # Phase 2: Temporary DH for Registration/Login
            print(f"\n{'='*60}")
            print(f"PHASE 2: TEMPORARY DH KEY EXCHANGE")
            print(f"{'='*60}")
            
            # Receive DH client params
            data = client_socket.recv(4096).decode('utf-8')
            dh_client = DHClientMessage(**json.loads(data))
            print(f"[<] Received DH_CLIENT (g={dh_client.g}, p={len(str(dh_client.p))} digits)")
            
            # Generate server DH keypair
            dh_server = DHKeyExchange()
            g, p, B = dh_server.get_public_params()
            
            # Compute shared secret
            K_s = dh_server.compute_shared_secret(dh_client.A)
            temp_key = derive_aes_key(K_s)
            print(f"[✓] Temporary session key derived (16 bytes)")
            
            # Send DH server response
            dh_response = DHServerMessage(B=B)
            client_socket.send(json.dumps(dh_response.dict()).encode('utf-8'))
            print(f"[>] Sent DH_SERVER")
            
            # Phase 3: Authentication (Register or Login)
            print(f"\n{'='*60}")
            print(f"PHASE 3: AUTHENTICATION")
            print(f"{'='*60}")
            
            # Receive encrypted auth message
            data = client_socket.recv(8192).decode('utf-8')
            auth_data = json.loads(data)
            
            # Decrypt auth message
            iv = b64d(auth_data['iv'])
            ct = b64d(auth_data['ct'])
            plaintext = aes_decrypt(iv, ct, temp_key).decode('utf-8')
            auth_msg = json.loads(plaintext)
            
            if auth_msg['type'] == 'register':
                print(f"[<] Received REGISTER request")
                username, success, message = self.handle_registration(auth_msg)
            elif auth_msg['type'] == 'login':
                print(f"[<] Received LOGIN request")
                username, success, message = self.handle_login(auth_msg)
            else:
                success = False
                message = "Invalid auth type"
            
            # Send encrypted auth response
            response = AuthResponseMessage(success=success, message=message)
            iv, ct = aes_encrypt(json.dumps(response.dict()).encode('utf-8'), temp_key)
            
            response_data = {
                'iv': b64e(iv),
                'ct': b64e(ct)
            }
            client_socket.send(json.dumps(response_data).encode('utf-8'))
            print(f"[>] Sent AUTH_RESPONSE: {message}")
            
            if not success:
                return
            
            # Phase 4: Session Key Agreement (Post-Auth DH)
            print(f"\n{'='*60}")
            print(f"PHASE 4: SESSION KEY AGREEMENT")
            print(f"{'='*60}")
            
            # Receive DH client for session
            data = client_socket.recv(4096).decode('utf-8')
            dh_client_session = DHClientMessage(**json.loads(data))
            print(f"[<] Received DH_CLIENT for session key")
            
            # Generate new DH keypair for session
            dh_session = DHKeyExchange()
            g, p, B = dh_session.get_public_params()
            
            # Compute shared secret
            K_s_session = dh_session.compute_shared_secret(dh_client_session.A)
            session_key = derive_aes_key(K_s_session)
            print(f"[✓] Session key established (16 bytes)")
            
            # Send DH server response
            dh_response_session = DHServerMessage(B=B)
            client_socket.send(json.dumps(dh_response_session.dict()).encode('utf-8'))
            print(f"[>] Sent DH_SERVER for session")
            
            # Initialize transcript
            transcript = TranscriptManager(role="server")
            
            # Phase 5: Data Plane - Encrypted Chat
            print(f"\n{'='*60}")
            print(f"PHASE 5: ENCRYPTED CHAT SESSION")
            print(f"{'='*60}")
            print(f"[*] Chat session active with user: {username}")
            print(f"[*] Type messages to send. Press Ctrl+C to end session.\n")
            
            # Start thread to handle incoming messages
            recv_thread = threading.Thread(
                target=self.receive_messages,
                args=(client_socket, session_key, client_cert, transcript, username)
            )
            recv_thread.daemon = True
            recv_thread.start()
            
            # Send messages from server console
            seqno = 1
            while True:
                try:
                    message = input("")
                    if not message:
                        continue
                    
                    # Encrypt message
                    iv, ct = aes_encrypt(message.encode('utf-8'), session_key)
                    
                    # Combine IV and ciphertext for transmission
                    full_ct = iv + ct
                    
                    # Create message with signature
                    ts = now_ms()
                    digest = compute_message_digest(seqno, ts, full_ct)
                    signature = sign_data(digest, self.server_key)
                    
                    chat_msg = ChatMessage(
                        seqno=seqno,
                        ts=ts,
                        ct=b64e(full_ct),
                        sig=b64e(signature)
                    )
                    
                    # Send message
                    client_socket.send(json.dumps(chat_msg.dict()).encode('utf-8'))
                    print(f"[{username}] {message}")
                    
                    # Add to transcript
                    transcript.add_entry(
                        seqno, ts, b64e(full_ct), b64e(signature),
                        client_fingerprint
                    )
                    
                    seqno += 1
                    
                except EOFError:
                    break
                except KeyboardInterrupt:
                    break
            
        except Exception as e:
            print(f"[!] Error handling client: {e}")
            import traceback
            traceback.print_exc()
        
        finally:
            # Phase 6: Session Teardown - Non-Repudiation
            if transcript:
                print(f"\n{'='*60}")
                print(f"PHASE 6: SESSION TEARDOWN - Non-Repudiation")
                print(f"{'='*60}")
                
                # Compute transcript hash
                transcript_hash = transcript.compute_transcript_hash()
                first_seq, last_seq = transcript.get_sequence_range()
                
                print(f"[*] Transcript hash: {transcript_hash}")
                
                # Sign transcript hash
                signature = sign_data(transcript_hash.encode('utf-8'), self.server_key)
                
                # Create session receipt
                receipt = SessionReceipt(
                    peer="server",
                    first_seq=first_seq,
                    last_seq=last_seq,
                    transcript_sha256=transcript_hash,
                    sig=b64e(signature)
                )
                
                # Save receipt
                transcript.save_receipt(
                    json.dumps(receipt.dict(), indent=2),
                    b64e(signature)
                )
                
                transcript.close()
                print(f"[✓] Session receipt generated and saved")
            
            client_socket.close()
            print(f"\n[+] Connection closed with {address}")
    
    def receive_messages(self, client_socket, session_key, client_cert, transcript, username):
        """Thread to receive and process incoming messages"""
        last_seqno = 0
        client_fingerprint = get_certificate_fingerprint(client_cert)
        
        while True:
            try:
                data = client_socket.recv(8192).decode('utf-8')
                if not data:
                    break
                
                msg = ChatMessage(**json.loads(data))
                
                # Replay protection
                if msg.seqno <= last_seqno:
                    print(f"\n[!] REPLAY ATTACK DETECTED: seqno {msg.seqno}")
                    error = ErrorMessage(code="REPLAY", message="Sequence number replay detected")
                    client_socket.send(json.dumps(error.dict()).encode('utf-8'))
                    continue
                
                last_seqno = msg.seqno
                
                # Verify signature
                full_ct = b64d(msg.ct)
                digest = compute_message_digest(msg.seqno, msg.ts, full_ct)
                signature = b64d(msg.sig)
                
                if not verify_signature(digest, signature, client_cert.public_key()):
                    print(f"\n[!] SIG_FAIL: Invalid signature on message {msg.seqno}")
                    error = ErrorMessage(code="SIG_FAIL", message="Signature verification failed")
                    client_socket.send(json.dumps(error.dict()).encode('utf-8'))
                    continue
                
                # Decrypt message
                iv = full_ct[:16]
                ct = full_ct[16:]
                plaintext = aes_decrypt(iv, ct, session_key).decode('utf-8')
                
                print(f"\n[Server] {plaintext}")
                
                # Add to transcript
                transcript.add_entry(
                    msg.seqno, msg.ts, msg.ct, msg.sig,
                    client_fingerprint
                )
                
            except Exception as e:
                print(f"\n[!] Error receiving message: {e}")
                break
    
    def handle_registration(self, auth_msg):
        """Handle user registration"""
        try:
            email = auth_msg['email']
            username = auth_msg['username']
            salt = b64d(auth_msg['salt'])
            pwd_hash = auth_msg['pwd']
            
            # Register user in database
            success, message = self.db.register_user(email, username, salt, pwd_hash)
            
            if success:
                return username, True, "Registration successful"
            else:
                return None, False, message
                
        except Exception as e:
            return None, False, f"Registration failed: {str(e)}"
    
    def handle_login(self, auth_msg):
        """Handle user login"""
        try:
            email = auth_msg['email']
            pwd_hash = auth_msg['pwd']
            
            # Authenticate user
            success, result = self.db.authenticate_user(email, pwd_hash)
            
            if success:
                username = result
                return username, True, f"Welcome back, {username}!"
            else:
                return None, False, result
                
        except Exception as e:
            return None, False, f"Login failed: {str(e)}"
    
    def load_cert_from_pem(self, pem_string):
        """Load certificate from PEM string"""
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        return x509.load_pem_x509_certificate(pem_string.encode('utf-8'), default_backend())
    
    def cleanup(self):
        """Cleanup server resources"""
        if self.server_socket:
            self.server_socket.close()
        if self.db:
            self.db.close()
        print("[+] Server shutdown complete")


def main():
    """Main entry point"""
    server = SecureChatServer(
        host=os.getenv('SERVER_HOST', 'localhost'),
        port=int(os.getenv('SERVER_PORT', 5000))
    )
    server.start()


if __name__ == "__main__":
    main()
