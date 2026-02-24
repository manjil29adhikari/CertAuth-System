# config.py
"""
CONFIGURATION SETTINGS FOR VENDOR AUTHENTICATION SYSTEM
"""
import os

# Base directory of the project
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Folder paths
CERT_DIR = os.path.join(BASE_DIR, "certs")
DB_DIR = os.path.join(BASE_DIR, "database")
AUTH_DIR = os.path.join(BASE_DIR, "auth")
DOCS_DIR = os.path.join(BASE_DIR, "docs")

# Create directories if they don't exist
for directory in [CERT_DIR, DB_DIR, AUTH_DIR, DOCS_DIR]:
    os.makedirs(directory, exist_ok=True)

# File paths
DATABASE_PATH = os.path.join(DB_DIR, "certauth.db")
ROOT_CA_CERT = os.path.join(CERT_DIR, "root_ca.crt")
ROOT_CA_KEY = os.path.join(CERT_DIR, "root_ca.key")
CRL_PATH = os.path.join(CERT_DIR, "crl.pem")
ADMIN_CREDENTIALS = os.path.join(AUTH_DIR, "admin_credentials.json")

# Cryptographic Settings (Industry Standards for PKI)
RSA_KEY_SIZE = 2048
ROOT_CA_KEY_SIZE = 4096
DEFAULT_PASSWORD = "certauth123"  # Should be changed in production
CERT_VALIDITY_DAYS = 365

# System Settings
SYSTEM_NAME = "Vendor Authentication PKI System"
ORGANIZATION_NAME = "CertAuth Organization"
COUNTRY_CODE = "NEPAL"
STATE = "KATHMANDU"
LOCALITY = "KALANKI"