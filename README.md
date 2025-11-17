
SecureChat - Encrypted Chat System
Assignment #2 - Information Security (CS-3002)
FAST-NUCES, Fall 2025
A console-based secure chat system implementing PKI, DH key exchange, AES-128 encryption, RSA signatures, and non-repudiation to achieve Confidentiality, Integrity, Authenticity, and Non-Repudiation (CIANR).

🔗 Repository Link
GitHub: https://github.com/YOUR_USERNAME/securechat-skeleton

📋 Features Implemented
✅ PKI Setup & Certificate Validation

Self-signed Root CA generation
Server and client X.509 certificates signed by CA
Mutual certificate validation (signature, expiry, CN checks)
Certificate fingerprinting for non-repudiation

✅ Secure Authentication

User registration with salted SHA-256 password hashing
MySQL storage for user credentials
Encrypted credential transmission using temporary DH key
No plaintext passwords in transit or storage

✅ Key Agreement

Diffie-Hellman key exchange (RFC 3526 Group 14)
Session key derivation: K = Trunc₁₆(SHA256(Ks))
Separate keys for auth and chat phases

✅ Encrypted Communication

AES-128 CBC encryption with PKCS#7 padding
Per-message RSA signatures over SHA256(seqno||ts||ct)
Sequence number-based replay protection
Tamper detection via signature verification

✅ Non-Repudiation

Append-only session transcripts
Signed session receipts with transcript hash
Offline verification of message integrity


🛠️ Setup Instructions
Prerequisites

Python 3.8+
MySQL 8.0+
Git

1. Clone Repository
bashgit clone https://github.com/YOUR_USERNAME/securechat-skeleton.git
cd securechat-skeleton
2. Create Virtual Environment
bashpython -m venv venv

# Activate:
# Windows:
venv\Scripts\activate
# Mac/Linux:
source venv/bin/activate
3. Install Dependencies
bashpip install -r requirements.txt
Required packages:

cryptography - For AES, RSA, DH, X.509
mysql-connector-python - For database
python-dotenv - For environment variables
pydantic - For message models

4. Setup MySQL Database
bash# Start MySQL (via Docker or local installation)
docker run -d --name securechat-db \
  -e MYSQL_ROOT_PASSWORD=rootpass \
  -e MYSQL_DATABASE=securechat \
  -e MYSQL_USER=scuser \
  -e MYSQL_PASSWORD=scpass \
  -p 3306:3306 mysql:8

# Or use local MySQL and create database:
mysql -u root -p
CREATE DATABASE securechat;
5. Configure Environment
bashcp .env.example .env
Edit .env:
envDB_HOST=localhost
DB_USER=scuser
DB_PASSWORD=scpass
DB_NAME=securechat
SERVER_HOST=localhost
SERVER_PORT=5000
6. Initialize Database
bashpython -m app.storage.db --init
7. Generate Certificates
bash# Generate Root CA
python scripts/gen_ca.py

# Generate Server Certificate
python scripts/gen_cert.py server localhost localhost 127.0.0.1

# Generate Client Certificate
python scripts/gen_cert.py client client1
Generated files:

certs/ca_key.pem - CA private key (keep secret!)
certs/ca_cert.pem - CA certificate
certs/server_key.pem - Server private key
certs/server_cert.pem - Server certificate
certs/client_key.pem - Client private key
certs/client_cert.pem - Client certificate


🚀 Running the Application
Start Server
bashpython -m app.server
Expected output:
[+] Connected to MySQL database
[+] Database schema initialized
[+] Server initialized on localhost:5000
[+] Server Certificate CN: CN=localhost,OU=Server,O=FAST-NUCES SecureChat...
[*] Server listening on localhost:5000
[*] Waiting for client connections...
Start Client (in new terminal)
bash# Activate venv first
source venv/bin/activate  # or venv\Scripts\activate on Windows

python -m app.client
Expected output:
[+] Client initialized
[+] Client Certificate CN: CN=client1,OU=Client,O=FAST-NUCES SecureChat...
[+] Connected to server at localhost:5000

PHASE 1: CONTROL PLANE - Certificate Exchange
[>] Sent HELLO to server
[<] Received SERVER_HELLO
[✓] Server certificate validated successfully
Usage Flow

Choose Authentication:

   [?] Choose action:
       1. Register new account
       2. Login with existing account
   Enter choice (1 or 2): 1

Register (if new user):

   Email: alice@example.com
   Username: alice
   Password: ********
   [>] Sent REGISTER request
   [<] Server response: Registration successful

Chat:

   PHASE 5: ENCRYPTED CHAT SESSION
   [*] Chat session active!
   [*] Type messages to send. Press Ctrl+C to end session.

   Hello Server!
   [You] Hello Server!
   [Server] Hi Alice!

End Session: Press Ctrl+C

   PHASE 6: SESSION TEARDOWN - Non-Repudiation
   [*] Transcript hash: a3f5c8d9e...
   [✓] Session receipt generated and saved

📁 Project Structure
securechat-skeleton/
├── app/
│   ├── client.py              # Client implementation
│   ├── server.py              # Server implementation
│   ├── common/
│   │   ├── protocol.py        # Pydantic message models
│   │   └── utils.py           # Helper functions
│   ├── crypto/
│   │   ├── aes.py             # AES-128 CBC encryption
│   │   ├── dh.py              # Diffie-Hellman key exchange
│   │   ├── pki.py             # Certificate validation
│   │   └── sign.py            # RSA digital signatures
│   └── storage/
│       ├── db.py              # MySQL user database
│       └── transcript.py      # Session transcript management
├── scripts/
│   ├── gen_ca.py              # Root CA generation
│   └── gen_cert.py            # Certificate generation
├── certs/                     # Certificates (gitignored)
├── transcripts/               # Session logs (gitignored)
├── .env                       # Config (gitignored)
├── .gitignore
├── requirements.txt
└── README.md

🧪 Testing & Evidence
Test 1: Wireshark - Encrypted Payloads
bash# Start Wireshark capture on loopback
sudo tcpdump -i lo -w securechat.pcap port 5000

# Run server and client
# After session, analyze:
wireshark securechat.pcap

# Filter: tcp.port == 5000
# Verify: No plaintext passwords or messages visible
Expected: All message content is base64-encoded ciphertext.
Test 2: Invalid Certificate Rejection
bash# Create self-signed cert (not by CA)
openssl req -x509 -newkey rsa:2048 -keyout fake_key.pem -out fake_cert.pem -days 1 -nodes

# Replace client_cert.pem with fake_cert.pem
# Start client






















# SecureChat – Assignment #2 (CS-3002 Information Security, Fall 2025)

This repository is the **official code skeleton** for your Assignment #2.  
You will build a **console-based, PKI-enabled Secure Chat System** in **Python**, demonstrating how cryptographic primitives combine to achieve:

**Confidentiality, Integrity, Authenticity, and Non-Repudiation (CIANR)**.


## 🧩 Overview

You are provided only with the **project skeleton and file hierarchy**.  
Each file contains docstrings and `TODO` markers describing what to implement.

Your task is to:
- Implement the **application-layer protocol**.
- Integrate cryptographic primitives correctly to satisfy the assignment spec.
- Produce evidence of security properties via Wireshark, replay/tamper tests, and signed session receipts.

## 🏗️ Folder Structure
```
securechat-skeleton/
├─ app/
│  ├─ client.py              # Client workflow (plain TCP, no TLS)
│  ├─ server.py              # Server workflow (plain TCP, no TLS)
│  ├─ crypto/
│  │  ├─ aes.py              # AES-128(ECB)+PKCS#7 (use cryptography lib)
│  │  ├─ dh.py               # Classic DH helpers + key derivation
│  │  ├─ pki.py              # X.509 validation (CA signature, validity, CN)
│  │  └─ sign.py             # RSA SHA-256 sign/verify (PKCS#1 v1.5)
│  ├─ common/
│  │  ├─ protocol.py         # Pydantic message models (hello/login/msg/receipt)
│  │  └─ utils.py            # Helpers (base64, now_ms, sha256_hex)
│  └─ storage/
│     ├─ db.py               # MySQL user store (salted SHA-256 passwords)
│     └─ transcript.py       # Append-only transcript + transcript hash
├─ scripts/
│  ├─ gen_ca.py              # Create Root CA (RSA + self-signed X.509)
│  └─ gen_cert.py            # Issue client/server certs signed by Root CA
├─ tests/manual/NOTES.md     # Manual testing + Wireshark evidence checklist
├─ certs/.keep               # Local certs/keys (gitignored)
├─ transcripts/.keep         # Session logs (gitignored)
├─ .env.example              # Sample configuration (no secrets)
├─ .gitignore                # Ignore secrets, binaries, logs, and certs
├─ requirements.txt          # Minimal dependencies
└─ .github/workflows/ci.yml  # Compile-only sanity check (no execution)
```

## ⚙️ Setup Instructions

1. **Fork this repository** to your own GitHub account(using official nu email).  
   All development and commits must be performed in your fork.

2. **Set up environment**:
   ```bash
   python3 -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt
   cp .env.example .env
   ```

3. **Initialize MySQL** (recommended via Docker):
   ```bash
   docker run -d --name securechat-db        -e MYSQL_ROOT_PASSWORD=rootpass        -e MYSQL_DATABASE=securechat        -e MYSQL_USER=scuser        -e MYSQL_PASSWORD=scpass        -p 3306:3306 mysql:8
   ```

4. **Create tables**:
   ```bash
   python -m app.storage.db --init
   ```

5. **Generate certificates** (after implementing the scripts):
   ```bash
   python scripts/gen_ca.py --name "FAST-NU Root CA"
   python scripts/gen_cert.py --cn server.local --out certs/server
   python scripts/gen_cert.py --cn client.local --out certs/client
   ```

6. **Run components** (after implementation):
   ```bash
   python -m app.server
   # in another terminal:
   python -m app.client
   ```

## 🚫 Important Rules

- **Do not use TLS/SSL or any secure-channel abstraction**  
  (e.g., `ssl`, HTTPS, WSS, OpenSSL socket wrappers).  
  All crypto operations must occur **explicitly** at the application layer.

- You are **not required** to implement AES, RSA, or DH math, Use any of the available libraries.
- Do **not commit secrets** (certs, private keys, salts, `.env` values).
- Your commits must reflect progressive development — at least **10 meaningful commits**.

## 🧾 Deliverables

When submitting on Google Classroom (GCR):

1. A ZIP of your **GitHub fork** (repository).
2. MySQL schema dump and a few sample records.
3. Updated **README.md** explaining setup, usage, and test outputs.
4. `RollNumber-FullName-Report-A02.docx`
5. `RollNumber-FullName-TestReport-A02.docx`

## 🧪 Test Evidence Checklist

✔ Wireshark capture (encrypted payloads only)  
✔ Invalid/self-signed cert rejected (`BAD_CERT`)  
✔ Tamper test → signature verification fails (`SIG_FAIL`)  
✔ Replay test → rejected by seqno (`REPLAY`)  
✔ Non-repudiation → exported transcript + signed SessionReceipt verified offline  
