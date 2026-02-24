# CertAuth – PKI Vendor Authentication System

**CertAuth** is a Public Key Infrastructure (PKI) based tool that provides authentication, data integrity, and confidentiality for vendors in a supply chain.  
It allows vendors to register, obtain X.509 digital certificates, sign quality documents, and securely share encrypted files or messages with other vendors.

This project was developed as part of the **ST6051CEM Practical Cryptography** coursework at Softwarica College.

---

## ✨ Features

- **PKI‑based Vendor Registration & Login**  
  – RSA key pair generation (2048‑bit) with per‑vendor random passwords.  
  – X.509 certificate issuance by a self‑signed Root CA (4096‑bit).  
  – Certificate‑based authentication (prove possession of private key).

- **Digital Signatures**  
  – Sign documents (e.g., quality certificates) using RSA‑PSS with SHA‑256.  
  – Verify signatures with the signer’s public key.  
  – All signed documents are stored in a SQLite database with an audit trail.

- **Encryption & Confidentiality**  
  – Hybrid encryption: AES‑256‑CBC for document content, RSA‑OAEP for the symmetric key.  
  – Optional password‑based key derivation (PBKDF2) for additional security.  
  – Encrypted file sharing between vendors (stored in the database).  
  – Secure end‑to‑end messaging with digital signatures.

- **Security Best Practices**  
  – Private keys are stored encrypted (PKCS#8, password‑protected).  
  – Certificate revocation list (CRL) and database flags for revoked certificates.  
  – Audit logging of all critical actions (login, signing, revocation, etc.).  
  – Tests simulate common attacks (revoked certificate usage, invalid signatures).

- **Administration**  
  – Admin panel to manage vendors, certificates, and audit logs.  
  – Approve/revoke vendors and certificates.  
  – Generate reports and send expiry reminders.

---

## 🛠️ Technology Stack

- **Language:** Python 3.9+  
- **GUI:** CustomTkinter  
- **Cryptography:** `cryptography` library  
- **Database:** SQLite3  
- **Testing:** `unittest` (built‑in)

---

## 📦 Installation

### Prerequisites

- Python 3.9 or higher  
- pip (Python package manager)

# CertAuth-System (PKI-Based Vendor Authentication)

CertAuth-System is a PKI-based vendor authentication platform. It provides:
- Admin portal for vendor lifecycle management and certificate operations
- Vendor portal for certificate-based login, document signing/verifying, encryption/decryption, and secure messaging
- Audit logs, reporting, and a test suite for crypto and security scenarios

---

## Step-by-Step Setup

### 1) Clone the repository
```bash
git clone https://github.com/manjil29adhikari/CertAuth-System.git
cd CertAuth-System

2) Create a virtual environment (recommended)

Linux / macOS

python -m venv venv
source venv/bin/activate

Windows (PowerShell)

python -m venv venv
venv\Scripts\Activate.ps1

Windows (CMD)

python -m venv venv
venv\Scripts\activate

3) Install dependencies
pip install -r requirements.txt

4) Run the application
python main.py

The main menu will open. From there you can access the Admin Portal or Vendor Portal.

🚀 Usage Guide
Admin Portal
Default credentials

Username: admin
Password: admin123
You will be forced to change the password on first login.

⚠️ Security note: These credentials are for local/demo use only. If you deploy beyond local testing, change credentials immediately and use environment variables / secrets management.

Capabilities

View and manage vendors (approve, suspend, revoke)

Issue and revoke certificates

View audit logs and system statistics

Send certificate expiry reminders via email (SMTP configuration required)

Generate reports (vendor performance, document status, security incidents)

Vendor Portal
Registration

From the main menu, choose Vendor Portal → New Vendor Registration

Fill in the company details and click REGISTER

The system generates an RSA key pair, issues an X.509 certificate, and displays your credentials

⚠️ Important: Save your private key password — it is required for login and signing.

Login

Select Vendor Portal → Existing Vendor Login

Enter your Vendor ID

Upload your certificate (.crt / .pem) and private key (.key / .pem)

Provide the private key password

The system validates the certificate and verifies private key ownership (challenge signing). On success, the vendor dashboard opens.

Dashboard features

Sign Document — Create a new document (optionally upload a file) and sign it with your private key. Stored in the database.

Verify Document — Paste a document + signature + signer’s public key/certificate to verify integrity and authenticity.

My Documents — View your signed documents and verification status.

Shared Documents — View documents shared by other vendors. Decrypt/read using your private key.

Encrypt/Decrypt — Encrypt for another vendor (their public key) or decrypt received encrypted files.

Secure Messaging — Send/receive encrypted messages between vendors.

Certificate — View your certificate details and validity status.

Profile — View your registered info and contact admin.

🧪 Testing

This project includes unit tests to verify cryptographic operations and simulate security scenarios.

Run all tests
python -m unittest discover tests
Individual test files

tests/test_crypto.py — key generation, signing, verification, encryption/decryption

tests/test_security.py — multi-user simulations and attack scenarios (revoked cert, invalid signature, replay attempts)

🤝 Contributing

Contributions are welcome!

Fork the repository

Create a feature branch

git checkout -b feature/amazing-feature

Commit your changes

git commit -m "Add some amazing feature"

Push to your branch

git push origin feature/amazing-feature

Open a Pull Request

Please follow the existing style, include docstrings, and add/update tests where appropriate.

::contentReference[oaicite:0]{index=0}