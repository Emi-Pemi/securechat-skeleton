#"""Client skeleton — plain TCP; no TLS. See assignment spec."""

##def main():
  #  raise NotImplementedError("students: implement client workflow")

##if __name__ == "__main__":
  #  main()

"""
Secure Chat Client
Connects to server, performs authentication, and enables encrypted chat
"""

import socket
import json
import threading
import os
import getpass
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
from app.storage.db import hash_password, generate_salt
from app.storage.transcript import TranscriptManager

load_dotenv()


class SecureChatClient:
    """Secure Chat Client"""
    
    def __init__(self, host='localhost', port=5000):
        self.host = host
        self.port = port
        self.socket = None
        
        # Load client certificate and private key
        self.client_cert = load_certificate_from_file('certs/client_cert.pem')
        self.client_key = load_private_key_from_file('certs/client_key.pem')
        
        # Load CA certificate for validation
        self.ca_cert = load_certificate_from_file('certs/ca_cert.pem')
        
        self.session_key = None
        self.server_cert = None
        self.transcript = None
        
        print(f"[+] Client initialized")
        print(f"[+] Client Certificate CN: {self.client_cert.subject.rfc4514_string()}")
    
    def connect(self):
        """Connect to the server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            print(f"\n[+] Connected to server at {self.host}:{self.port}")
            return True
        except Exception as e:
            print(f"[!] Connection failed: {e}")
            return False
    
    def run(self):
        """Main client workflow"""
        if not self.connect():
            return
        
        try:
            # Phase 1: Control Plane - Certificate Exchange
            print(f"\n{'='*60}")
            print(f"PHASE 1: CONTROL PLANE - Certificate Exchange")
            print(f"{'='*60}")
            
            # Send client hello
            hello = HelloMessage(
                client_cert=cert_to_pem_string(self.client_cert),
                nonce=b64e(os.urandom(16))
            )
            self.socket.send(json.dumps(hello.dict()).encode('utf-8'))
            print(f"[>] Sent HELLO to server")
            
            # Receive server hello
            data = self.socket.recv(8192).decode('utf-8')
            response = json.loads(data)
            
            # Check for error
            if response.get('type') == 'error':
                error = ErrorMessage(**response)
                print(f"[!] Server error: {error.code} - {error.message}")
                return
            
            server_hello = ServerHelloMessage(**response)
            print(f"[<] Received SERVER_HELLO")
            
            # Validate server certificate
            self.server_cert = self.load_cert_from_pem(server_hello.server_cert)
            is_valid, msg = validate_certificate(self.server_cert, self.ca_cert)
            
            if not is_valid:
                print(f"[!] Server certificate validation failed: {msg}")
                return
            
            print(f"[✓] Server certificate validated successfully")
            server_fingerprint = get_certificate_fingerprint(self.server_cert)
            print(f"    Server fingerprint: {server_fingerprint[:16]}...")
            
            # Phase 2: Temporary DH for Authentication
            print(f"\n{'='*60}")
            print(f"PHASE 2: TEMPORARY DH KEY EXCHANGE")
            print(f"{'='*60}")
            
            # Generate DH keypair
            dh_client = DHKeyExchange()
            g, p, A = dh_client.get_public_params()
            
            # Send DH client params
            dh_msg = DHClientMessage(g=g, p=p, A=A)
            self.socket.send(json.dumps(dh_msg.dict()).encode('utf-8'))
            print(f"[>] Sent DH_CLIENT")
            
            # Receive DH server response
            data = self.socket.recv(4096).decode('utf-8')
            dh_server = DHServerMessage(**json.loads(data))
            print(f"[<] Received DH_SERVER")
            
            # Compute shared secret and derive temp key
            K_s = dh_client.compute_shared_secret(dh_server.B)
            temp_key = derive_aes_key(K_s)
            print(f"[✓] Temporary session key derived (16 bytes)")
            
            # Phase 3: Authentication
            print(f"\n{'='*60}")
            print(f"PHASE 3: AUTHENTICATION")
            print(f"{'='*60}")
            
            # Ask user for register or login
            print("\n[?] Choose action:")
            print("    1. Register new account")
            print("    2. Login with existing account")
            choice = input("Enter choice (1 or 2): ").strip()
            
            if choice == '1':
                success = self.register(temp_key)
            elif choice == '2':
                success = self.login(temp_key)
            else:
                print("[!] Invalid choice")
                return
            
            if not success:
                print("[!] Authentication failed")
                return
            
            # Phase 4: Session Key Agreement (Post-Auth DH)
            print(f"\n{'='*60}")
            print(f"PHASE 4: SESSION KEY AGREEMENT")
            print(f"{'='*60}")
            
            # Generate new DH keypair for session
            dh_session = DHKeyExchange()
            g, p, A = dh_session.get_public_params()
            
            # Send DH client params
            dh_msg_session = DHClientMessage(g=g, p=p, A=A)
            self.socket.send(json.dumps(dh_msg_session.dict()).encode('utf-8'))
            print(f"[>] Sent DH_CLIENT for session key")
            
            # Receive DH server response
            data = self.socket.recv(4096).decode('utf-8')
            dh_server_session = DHServerMessage(**json.loads(data))
            print(f"[<] Received DH_SERVER for session")
            
            # Compute shared secret and derive session key
            K_s_session = dh_session.compute_shared_secret(dh_server_session.B)
            self.session_key = derive_aes_key(K_s_session)
            print(f"[✓] Session key established (16 bytes)")
            
            # Initialize transcript
            self.transcript = TranscriptManager(role="client")
            
            # Phase 5: Data Plane - Encrypted Chat
            print(f"\n{'='*60}")
            print(f"PHASE 5: ENCRYPTED CHAT SESSION")
            print(f"{'='*60}")
            print(f"[*] Chat session active!")
            print(f"[*] Type messages to send. Press Ctrl+C to end session.\n")
            
            # Start thread to receive messages
            recv_thread = threading.Thread(target=self.receive_messages)
            recv_thread.daemon = True
            recv_thread.start()
            
            # Send messages
            self.send_messages()
            
        except KeyboardInterrupt:
            print("\n[!] Disconnecting...")
        except Exception as e:
            print(f"[!] Error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            self.disconnect()
    
    def register(self, temp_key):
        """Handle user registration"""
        print("\n[*] Registration")
        email = input("Email: ").strip()
        username = input("Username: ").strip()
        password = getpass.getpass("Password: ")
        
        # Generate salt and hash password
        salt = generate_salt()
        pwd_hash = hash_password(password, salt)
        
        # Create registration message
        reg_msg = RegisterMessage(
            email=email,
            username=username,
            pwd=pwd_hash,
            salt=b64e(salt)
        )
        
        # Encrypt registration message
        iv, ct = aes_encrypt(json.dumps(reg_msg.dict()).encode('utf-8'), temp_key)
        
        # Send encrypted registration
        encrypted_msg = {
            'type': 'auth',
            'iv': b64e(iv),
            'ct': b64e(ct)
        }
        self.socket.send(json.dumps(encrypted_msg).encode('utf-8'))
        print(f"[>] Sent REGISTER request")
        
        # Receive response
        data = self.socket.recv(4096).decode('utf-8')
        response_data = json.loads(data)
        
        # Decrypt response
        iv = b64d(response_data['iv'])
        ct = b64d(response_data['ct'])
        plaintext = aes_decrypt(iv, ct, temp_key).decode('utf-8')
        response = AuthResponseMessage(**json.loads(plaintext))
        
        print(f"[<] Server response: {response.message}")
        return response.success
    
    def login(self, temp_key):
        """Handle user login"""
        print("\n[*] Login")
        email = input("Email: ").strip()
        password = getpass.getpass("Password: ")
        
        # For login, we need to get the salt from server first
        # In this simplified version, we'll send email and let server handle it
        # In production, you'd query salt first, then hash
        
        # For now, we'll use a dummy salt (server will retrieve actual salt)
        salt = generate_salt()
        pwd_hash = hash_password(password, salt)
        
        # Create login message
        login_msg = LoginMessage(
            email=email,
            pwd=pwd_hash,
            nonce=b64e(os.urandom(16))
        )
        
        # Encrypt login message
        iv, ct = aes_encrypt(json.dumps(login_msg.dict()).encode('utf-8'), temp_key)
        
        # Send encrypted login
        encrypted_msg = {
            'type': 'auth',
            'iv': b64e(iv),
            'ct': b64e(ct)
        }
        self.socket.send(json.dumps(encrypted_msg).encode('utf-8'))
        print(f"[>] Sent LOGIN request")
        
        # Receive response
        data = self.socket.recv(4096).decode('utf-8')
        response_data = json.loads(data)
        
        # Decrypt response
        iv = b64d(response_data['iv'])
        ct = b64d(response_data['ct'])
        plaintext = aes_decrypt(iv, ct, temp_key).decode('utf-8')
        response = AuthResponseMessage(**json.loads(plaintext))
        
        print(f"[<] Server response: {response.message}")
        return response.success
    
    def send_messages(self):
        """Send messages to server"""
        seqno = 1
        server_fingerprint = get_certificate_fingerprint(self.server_cert)
        
        while True:
            try:
                message = input("")
                if not message:
                    continue
                
                # Encrypt message
                iv, ct = aes_encrypt(message.encode('utf-8'), self.session_key)
                
                # Combine IV and ciphertext
                full_ct = iv + ct
                
                # Create message with signature
                ts = now_ms()
                digest = compute_message_digest(seqno, ts, full_ct)
                signature = sign_data(digest, self.client_key)
                
                chat_msg = ChatMessage(
                    seqno=seqno,
                    ts=ts,
                    ct=b64e(full_ct),
                    sig=b64e(signature)
                )
                
                # Send message
                self.socket.send(json.dumps(chat_msg.dict()).encode('utf-8'))
                print(f"[You] {message}")
                
                # Add to transcript
                self.transcript.add_entry(
                    seqno, ts, b64e(full_ct), b64e(signature),
                    server_fingerprint
                )
                
                seqno += 1
                
            except EOFError:
                break
            except KeyboardInterrupt:
                break
    
    def receive_messages(self):
        """Receive messages from server"""
        last_seqno = 0
        server_fingerprint = get_certificate_fingerprint(self.server_cert)
        
        while True:
            try:
                data = self.socket.recv(8192).decode('utf-8')
                if not data:
                    break
                
                msg_data = json.loads(data)
                
                # Check for errors
                if msg_data.get('type') == 'error':
                    error = ErrorMessage(**msg_data)
                    print(f"\n[!] Error: {error.code} - {error.message}")
                    continue
                
                msg = ChatMessage(**msg_data)
                
                # Replay protection
                if msg.seqno <= last_seqno:
                    print(f"\n[!] REPLAY ATTACK DETECTED: seqno {msg.seqno}")
                    continue
                
                last_seqno = msg.seqno
                
                # Verify signature
                full_ct = b64d(msg.ct)
                digest = compute_message_digest(msg.seqno, msg.ts, full_ct)
                signature = b64d(msg.sig)
                
                if not verify_signature(digest, signature, self.server_cert.public_key()):
                    print(f"\n[!] SIG_FAIL: Invalid signature on message {msg.seqno}")
                    continue
                
                # Decrypt message
                iv = full_ct[:16]
                ct = full_ct[16:]
                plaintext = aes_decrypt(iv, ct, self.session_key).decode('utf-8')
                
                print(f"\n[Server] {plaintext}")
                
                # Add to transcript
                self.transcript.add_entry(
                    msg.seqno, msg.ts, msg.ct, msg.sig,
                    server_fingerprint
                )
                
            except Exception as e:
                print(f"\n[!] Error receiving message: {e}")
                break
    
    def disconnect(self):
        """Disconnect and generate session receipt"""
        if self.transcript:
            print(f"\n{'='*60}")
            print(f"PHASE 6: SESSION TEARDOWN - Non-Repudiation")
            print(f"{'='*60}")
            
            # Compute transcript hash
            transcript_hash = self.transcript.compute_transcript_hash()
            first_seq, last_seq = self.transcript.get_sequence_range()
            
            print(f"[*] Transcript hash: {transcript_hash}")
            
            # Sign transcript hash
            signature = sign_data(transcript_hash.encode('utf-8'), self.client_key)
            
            # Create session receipt
            receipt = SessionReceipt(
                peer="client",
                first_seq=first_seq,
                last_seq=last_seq,
                transcript_sha256=transcript_hash,
                sig=b64e(signature)
            )
            
            # Save receipt
            self.transcript.save_receipt(
                json.dumps(receipt.dict(), indent=2),
                b64e(signature)
            )
            
            self.transcript.close()
            print(f"[✓] Session receipt generated and saved")
        
        if self.socket:
            self.socket.close()
            print(f"\n[+] Disconnected from server")
    
    def load_cert_from_pem(self, pem_string):
        """Load certificate from PEM string"""
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        return x509.load_pem_x509_certificate(pem_string.encode('utf-8'), default_backend())


def main():
    """Main entry point"""
    client = SecureChatClient(
        host=os.getenv('SERVER_HOST', 'localhost'),
        port=int(os.getenv('SERVER_PORT', 5000))
    )
    client.run()


if __name__ == "__main__":
    main()
