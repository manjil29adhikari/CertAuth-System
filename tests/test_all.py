"""
Combined unit and security tests for CertAuth.
Tests core cryptographic functions, multi-user signing/verification, and common attack simulations.
Includes a DB-backed revocation test (CRL table) that matches the actual system behavior.
"""

import unittest
import os
import sys
import tempfile
import sqlite3
import base64
import hashlib
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.certificate_engine import CertificateEngine
from crypto.ca_manager import CertificateAuthorityManager
from crypto.encryption import EncryptionManager
from database.models import DatabaseManager


# ==================== CRYPTO ENGINE TESTS ====================

class TestCryptoEngine(unittest.TestCase):
    """Test the core cryptographic engine (key generation, signing, verification)."""

    def setUp(self):
        self.engine = CertificateEngine()

    def test_key_generation(self):
        keys = self.engine.generate_key_pair()
        self.assertIn("private_key", keys)
        self.assertIn("public_key", keys)
        self.assertIn("password", keys)
        self.assertGreater(len(keys["password"]), 8)

    def test_sign_and_verify(self):
        keys = self.engine.generate_key_pair()
        document = "This is a test document."
        signature = self.engine.sign_document(keys["private_key"], document, keys["password"])
        self.assertIsNotNone(signature)

        valid = self.engine.verify_signature(keys["public_key"], document, signature)
        self.assertTrue(valid)

        valid = self.engine.verify_signature(keys["public_key"], document + " tampered", signature)
        self.assertFalse(valid)

        fake_signature = base64.b64encode(b"fake").decode()
        valid = self.engine.verify_signature(keys["public_key"], document, fake_signature)
        self.assertFalse(valid)

    def test_wrong_password_fails(self):
        keys = self.engine.generate_key_pair()
        with self.assertRaises(Exception):
            self.engine.sign_document(keys["private_key"], "Secret", "wrong_password")


# ==================== CA MANAGER TESTS ====================

class TestCAManager(unittest.TestCase):
    """Test Certificate Authority operations (issuance, validation, expiry)."""

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.original_cwd = os.getcwd()
        os.chdir(cls.temp_dir.name)

        os.makedirs("certs", exist_ok=True)

        cls.ca = CertificateAuthorityManager()
        cls.ca.load_or_create_ca()

    @classmethod
    def tearDownClass(cls):
        os.chdir(cls.original_cwd)
        cls.temp_dir.cleanup()

    def setUp(self):
        self.engine = CertificateEngine()
        self.vendor_keys = self.engine.generate_key_pair()
        self.vendor_data = {
            "company_name": "Test Supplier Inc.",
            "email": "test@supplier.com",
            "vendor_id": "VENDTEST001",
            "city": "Testville",
            "state": "TestState",
        }

    def test_issue_certificate(self):
        cert_info = self.ca.issue_vendor_certificate(
            self.vendor_data,
            self.vendor_keys["public_key"],
            validity_days=30
        )
        self.assertIn("serial_number", cert_info)
        self.assertIn("certificate_pem", cert_info)
        self.assertEqual(cert_info["status"], "active")

        is_valid, reason = self.ca.validate_certificate(cert_info["certificate_pem"])
        self.assertTrue(is_valid, reason)

    def test_expired_certificate(self):
        cert_info = self.ca.issue_vendor_certificate(
            self.vendor_data,
            self.vendor_keys["public_key"],
            validity_days=1
        )

        future_time = datetime.now(timezone.utc) + timedelta(days=2)

        with patch("crypto.ca_manager.datetime") as mock_datetime:
            mock_datetime.now.return_value = future_time
            mock_datetime.utcnow = mock_datetime.now
            is_valid, reason = self.ca.validate_certificate(cert_info["certificate_pem"])
            self.assertFalse(is_valid)
            self.assertIn("expired", reason.lower())


# ==================== ENCRYPTION MANAGER TESTS ====================

class TestEncryptionManager(unittest.TestCase):
    """Test hybrid encryption and decryption."""

    def setUp(self):
        self.engine = CertificateEngine()
        self.sender_keys = self.engine.generate_key_pair()
        self.recipient_keys = self.engine.generate_key_pair()
        self.plaintext = "This is a confidential document."

    def test_encrypt_decrypt(self):
        encrypted = EncryptionManager.encrypt_document(
            content=self.plaintext,
            public_key_pem=self.recipient_keys["public_key"]
        )
        self.assertIn("encrypted_content", encrypted)
        self.assertIn("encrypted_key", encrypted)

        decrypted = EncryptionManager.decrypt_document(
            encrypted_data=encrypted,
            private_key_pem=self.recipient_keys["private_key"],
            password=self.recipient_keys["password"]
        )
        self.assertEqual(decrypted, self.plaintext)

    def test_with_password(self):
        password = "extra_secret"
        encrypted = EncryptionManager.encrypt_document(
            content=self.plaintext,
            public_key_pem=self.recipient_keys["public_key"],
            password=password
        )
        self.assertIsNotNone(encrypted.get("salt"))

        decrypted = EncryptionManager.decrypt_document(
            encrypted_data=encrypted,
            private_key_pem=self.recipient_keys["private_key"],
            password=self.recipient_keys["password"]
        )
        self.assertEqual(decrypted, self.plaintext)


# ==================== MULTI-USER SCENARIO TESTS ====================

class TestMultiUserScenario(unittest.TestCase):
    """Simulate multiple vendors registering, signing, and verifying documents."""

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.original_cwd = os.getcwd()
        os.chdir(cls.temp_dir.name)

        os.makedirs("certs", exist_ok=True)
        os.makedirs("database", exist_ok=True)

        cls.db_path = os.path.join("database", "test.db")
        cls.db = DatabaseManager(db_path=cls.db_path)
        cls.ca = CertificateAuthorityManager()
        cls.engine = CertificateEngine()

    @classmethod
    def tearDownClass(cls):
        os.chdir(cls.original_cwd)
        cls.temp_dir.cleanup()

    def setUp(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        tables = ["vendors", "certificates", "signed_documents", "shared_documents", "secure_messages", "audit_log", "crl"]
        for table in tables:
            try:
                cursor.execute(f"DELETE FROM {table}")
            except Exception:
                pass
        conn.commit()
        conn.close()

    def test_two_vendors_sign_and_verify(self):
        vendor_a_data = {"company_name": "Vendor A Inc.", "email": "a@example.com", "contact_person": "Alice"}
        vendor_a_id = self.db.register_vendor(vendor_a_data)
        keys_a = self.engine.generate_key_pair()
        cert_a = self.ca.issue_vendor_certificate(
            vendor_data={**vendor_a_data, "vendor_id": vendor_a_id},
            public_key_pem=keys_a["public_key"],
            validity_days=30
        )
        self.db.update_vendor_certificate(vendor_a_id, keys_a["public_key"], cert_a["serial_number"])

        vendor_b_data = {"company_name": "Vendor B Ltd.", "email": "b@example.com", "contact_person": "Bob"}
        vendor_b_id = self.db.register_vendor(vendor_b_data)
        keys_b = self.engine.generate_key_pair()
        cert_b = self.ca.issue_vendor_certificate(
            vendor_data={**vendor_b_data, "vendor_id": vendor_b_id},
            public_key_pem=keys_b["public_key"],
            validity_days=30
        )
        self.db.update_vendor_certificate(vendor_b_id, keys_b["public_key"], cert_b["serial_number"])

        document = "Quality certificate for batch #12345"
        signature = self.engine.sign_document(keys_a["private_key"], document, keys_a["password"])

        valid = self.engine.verify_signature(keys_a["public_key"], document, signature)
        self.assertTrue(valid)

        valid = self.engine.verify_signature(keys_a["public_key"], document + " tampered", signature)
        self.assertFalse(valid)


# ==================== UNAUTHORIZED SIGNING (IMPERSONATION) TEST ====================

class TestUnauthorizedSigning(unittest.TestCase):
    """
    Unauthorized signing prevention (impersonation):
    Attacker signs with their own private key but claims they are Vendor A.
    Verification using Vendor A's public key MUST fail.
    """

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.original_cwd = os.getcwd()
        os.chdir(cls.temp_dir.name)

        os.makedirs("certs", exist_ok=True)
        os.makedirs("database", exist_ok=True)

        cls.db_path = os.path.join("database", "test.db")
        cls.db = DatabaseManager(db_path=cls.db_path)
        cls.ca = CertificateAuthorityManager()
        cls.engine = CertificateEngine()

        cls.vendor_a_data = {"company_name": "Vendor A Inc.", "email": "a@example.com", "contact_person": "Alice"}
        cls.vendor_a_id = cls.db.register_vendor(cls.vendor_a_data)
        cls.keys_a = cls.engine.generate_key_pair()

        cls.cert_a = cls.ca.issue_vendor_certificate(
            vendor_data={**cls.vendor_a_data, "vendor_id": cls.vendor_a_id},
            public_key_pem=cls.keys_a["public_key"],
            validity_days=30
        )
        cls.db.update_vendor_certificate(cls.vendor_a_id, cls.keys_a["public_key"], cls.cert_a["serial_number"])

    @classmethod
    def tearDownClass(cls):
        os.chdir(cls.original_cwd)
        cls.temp_dir.cleanup()

    def test_attacker_cannot_sign_as_vendor_a(self):
        attacker_keys = self.engine.generate_key_pair()
        document = "Quality certificate for batch #99999"

        forged_signature = self.engine.sign_document(
            attacker_keys["private_key"], document, attacker_keys["password"]
        )

        valid = self.engine.verify_signature(self.keys_a["public_key"], document, forged_signature)
        self.assertFalse(valid, "Forged signature should NOT verify with Vendor A public key")


# ==================== ATTACK SIMULATION TESTS ====================

class TestAttackSimulations(unittest.TestCase):
    """Simulate common attacks and verify that the system detects them."""

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.original_cwd = os.getcwd()
        os.chdir(cls.temp_dir.name)

        os.makedirs("certs", exist_ok=True)
        os.makedirs("database", exist_ok=True)

        cls.db_path = os.path.join("database", "test.db")
        cls.db = DatabaseManager(db_path=cls.db_path)
        cls.ca = CertificateAuthorityManager()
        cls.engine = CertificateEngine()

        cls.victim_data = {"company_name": "Victim Corp", "email": "victim@example.com", "contact_person": "Victor"}
        cls.victim_id = cls.db.register_vendor(cls.victim_data)
        cls.victim_keys = cls.engine.generate_key_pair()
        cls.victim_cert = cls.ca.issue_vendor_certificate(
            vendor_data={**cls.victim_data, "vendor_id": cls.victim_id},
            public_key_pem=cls.victim_keys["public_key"],
            validity_days=30
        )
        cls.db.update_vendor_certificate(cls.victim_id, cls.victim_keys["public_key"], cls.victim_cert["serial_number"])

        # Store cert in DB for revocation workflow (optional but realistic)
        cls.db.store_certificate({
            "serial": cls.victim_cert["serial_number"],
            "vendor_id": cls.victim_id,
            "issuer": cls.victim_cert["issuer"],
            "subject": cls.victim_cert["subject"],
            "not_valid_before": cls.victim_cert["not_valid_before"],
            "not_valid_after": cls.victim_cert["not_valid_after"],
            "certificate_data": cls.victim_cert["certificate_pem"],
        })

    @classmethod
    def tearDownClass(cls):
        os.chdir(cls.original_cwd)
        cls.temp_dir.cleanup()

    def test_revoked_certificate_rejected_db_crl(self):
        """
        Revocation test using the system's DB CRL table (authoritative in this implementation).
        This matches how DatabaseManager.revoke_certificate() writes to the 'crl' table.
        """
        serial = self.victim_cert["serial_number"]

        # Revoke using DB manager (writes to SQLite CRL table)
        self.db.revoke_certificate(serial, reason_code=1, reason_text="Test revocation")

        # DB should show revoked
        self.assertTrue(self.db.is_certificate_revoked(serial))

        # Vendor status should become revoked (DatabaseManager.revoke_certificate updates vendors.status)
        victim = self.db.get_vendor_by_id(self.victim_id)
        self.assertEqual(victim["status"], "revoked")

    def test_signature_forgery_detected(self):
        attacker_keys = self.engine.generate_key_pair()
        document = "Original document"
        forged_signature = self.engine.sign_document(attacker_keys["private_key"], document, attacker_keys["password"])

        valid = self.engine.verify_signature(self.victim_keys["public_key"], document, forged_signature)
        self.assertFalse(valid)

    def test_man_in_the_middle_prevention(self):
        """
        MITM simulation:
        Attacker uses a fake CA to issue a cert for the victim identity.
        Trusted CA validation must reject it.
        """
        current_dir = os.getcwd()
        fake_ca_dir = os.path.join(self.temp_dir.name, "fake_ca")
        os.makedirs(fake_ca_dir, exist_ok=True)
        os.chdir(fake_ca_dir)

        os.makedirs("certs", exist_ok=True)
        fake_ca = CertificateAuthorityManager()
        fake_ca.create_root_ca()

        attacker_keys = self.engine.generate_key_pair()
        fake_cert_info = fake_ca.issue_vendor_certificate(
            vendor_data=self.victim_data,
            public_key_pem=attacker_keys["public_key"],
            validity_days=30
        )

        os.chdir(current_dir)

        is_valid, reason = self.ca.validate_certificate(fake_cert_info["certificate_pem"])
        self.assertFalse(is_valid)


# ==================== RUN ALL TESTS ====================

if __name__ == "__main__":
    unittest.main()