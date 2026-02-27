# CertAuth – Vendor Authentication System (PKI)

**CertAuth** is a Public Key Infrastructure (PKI) based application that provides **vendor identity assurance**, **document integrity**, **revocation enforcement**, and **confidential exchange** for vendor ecosystems.  
Vendors can register and receive **X.509 certificates**, digitally sign documents, verify authenticity, securely share encrypted files, and exchange secure messages. Administrators manage vendor lifecycle controls, certificate issuance/revocation, and audit evidence.

Developed for **ST6051CEM Practical Cryptography** at **Softwarica College of IT & E-Commerce (in collaboration with Coventry University)**.

---

## ✨ Key Features

### PKI-based Vendor Identity
- RSA key pair generation (2048-bit) with **password-encrypted PKCS#8** private keys.
- X.509 certificate issuance by a **self-signed Root CA** (4096-bit).
- Vendor lifecycle status: pending/active/suspended/revoked.

### Digital Signatures (Integrity + Evidence)
- Sign documents using **RSA-PSS + SHA-256**.
- Verify signatures and detect tampering/forgery.
- Signed document records stored in SQLite for traceability.

### Confidential Sharing (Hybrid Encryption)
- Hybrid encryption:
  - **AES-CBC** for content encryption
  - **RSA-OAEP** for encrypting the AES key
- Encrypted shared documents stored in SQLite.

### Secure Messaging
- Encrypted vendor-to-vendor messages stored in SQLite.

### Revocation + Auditability
- Revocation enforced using CRL tracking and lifecycle status.
- Audit logging for security-relevant actions (admin + vendor).

---

## 🧱 Technology Stack
- **Language:** Python 3.x  
- **GUI:** CustomTkinter  
- **Crypto:** `cryptography` library  
- **Database:** SQLite  
- **Testing:** `unittest`

---

# ✅ Run Options

## Option A (Recommended): Run with Docker (GUI in Browser)

This option allows your lecturer to run CertAuth with **one command**, without installing Python dependencies.  
The GUI opens in a browser using **noVNC**.

### Prerequisites
- Docker Desktop (Windows/Mac) or Docker Engine (Linux)

### 1) Clone the repository
```bash
git clone https://github.com/manjil29adhikari/CertAuth-System.git
cd CertAuth-System

2) (Recommended) Create an exports folder on host
This folder is used to store downloaded vendor credential files and PEM files outside the container:
mkdir exports

3) Build and run
docker compose up --build

4) Open the GUI
Open in a browser:
http://localhost:6080/vnc.html

5) Saving files while using Docker (important)
When CertAuth asks you to save a file (credential document / key / certificate), save it inside the container to:
✅ /app/exports
Because ./exports is mounted to /app/exports, the saved files will appear on your host machine in:
✅ ./exports
Stop Docker
docker compose down



Option B: Run Locally with Python
Prerequisites:
=>Python 3.9+ (recommended)
=> pip

1) Create a virtual environment (recommended)

Windows (PowerShell)
python -m venv venv
venv\Scripts\Activate.ps1

Windows (CMD)
python -m venv venv
venv\Scripts\activate

Linux/macOS
python -m venv venv
source venv/bin/activate

2) Install dependencies
pip install -r requirements.txt

3) Run the application
python main.py


🚀 Usage Guide

**Admin Portal**

*Default credentials*

Username: admin
Password: admin123
(You will be forced to change the password on first login.)


Admin manages vendor approvals, suspension/revocation, certificates, CRL enforcement, and audit review.

Common actions:

Approve/activate vendor

Suspend vendor (temporary restriction)

Revoke vendor certificate (CRL enforcement)

Review audit trail and generate reports

Vendor Portal
1) New Vendor Registration (Credential Document)

From the main menu, choose:

Vendor Portal → New Vendor Registration

After submitting the registration form, CertAuth generates a Vendor Credential Document (text file).
This credential file contains everything the vendor needs for login and cryptographic operations:

Vendor ID

Private Key Password

PRIVATE KEY (PEM block)

CERTIFICATE (PEM block)

✅ These values are required for vendor login and for signing/decrypting operations.
⚠️ Keep the credential file secure because it contains sensitive material.

If running in Docker: save this credential document to:

/app/exports
so it appears on your host in ./exports.

2) Prepare Login Files (Split the Credential Document into 2 PEM files)

Before logging in, the vendor must create two separate PEM files from the credential document.

A) Create the Private Key file (.pem)

Open the credential document in a text editor.

Copy the full block starting from:

-----BEGIN ENCRYPTED PRIVATE KEY-----

and ending at:

-----END ENCRYPTED PRIVATE KEY-----

Paste into a new text file and save as:

vendor_private_key.pem

B) Create the Certificate file (.pem)

In the same credential document, copy the full block starting from:

-----BEGIN CERTIFICATE-----

and ending at:

-----END CERTIFICATE-----

Paste into a new text file and save as:

vendor_certificate.pem

✅ After this step, the vendor should have:

vendor_private_key.pem

vendor_certificate.pem

If running in Docker: store these files in:

/app/exports
so they appear on your host in ./exports.

3) Vendor Login

From the main menu, choose:

Vendor Portal → Existing Vendor Login

Provide:

Vendor ID (from credential document)

Private Key Password (from credential document)

Select/upload:

vendor_private_key.pem

vendor_certificate.pem

The system validates certificate trust (issuer/validity/revocation) and verifies private key ownership before granting access.

🧪 Testing
This project uses unittest and includes the combined test suite:
tests/test_all.py
Run tests
python -m unittest tests/test_all.py
Or run discovery
python -m unittest discover -s tests

What is validated:
RSA key generation and encrypted private key handling
RSA-PSS signing and signature verification (tamper detection)
Hybrid encryption (encrypt/decrypt)
Multi-user workflows and adversarial checks:
tampering detection
impersonation attempt fails verification
revocation enforcement via CRL/DB logic

📁 Project Structure (High-level)

gui/ – UI workflows (Admin Panel, Vendor Portal, Main Menu)
crypto/ – CA manager, certificate engine, encryption manager
database/ – SQLite schema and persistence
auth/ – Admin authentication logic
certs/ – Root CA and CRL artifacts
tests/ – Automated tests (test_all.py)
main.py – Entry point