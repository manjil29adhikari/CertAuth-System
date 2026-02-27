"""
CERTIFICATE AUTHORITY MANAGER for CertAuth: Vendor Authentication System PKI
Handles certificate lifecycle: issuance, validation, revocation
"""
import os
import sys
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509 import ReasonFlags
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import base64

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import timezone

def _get_cert_validity_utc(cert):
    """
    Compatibility helper for cryptography versions:
    - Newer: cert.not_valid_before_utc / not_valid_after_utc
    - Older: cert.not_valid_before / not_valid_after (naive datetimes)
    """
    if hasattr(cert, "not_valid_before_utc") and hasattr(cert, "not_valid_after_utc"):
        return cert.not_valid_before_utc, cert.not_valid_after_utc

    # Older versions
    nvb = cert.not_valid_before
    nva = cert.not_valid_after

    # Make timezone-aware (UTC)
    if nvb.tzinfo is None:
        nvb = nvb.replace(tzinfo=timezone.utc)
    if nva.tzinfo is None:
        nva = nva.replace(tzinfo=timezone.utc)

    return nvb, nva

class CertificateAuthorityManager:
    def __init__(self, ca_cert_path="certs/root_ca.crt", ca_key_path="certs/root_ca.key",
                 crl_path="certs/crl.pem"):
        """
        Initialize CA CertAuth: Vendor Authentication System
        """
        self.ca_cert_path = ca_cert_path
        self.ca_key_path = ca_key_path
        self.crl_path = crl_path

        # Create certs directory if it doesn't exist
        os.makedirs(os.path.dirname(self.crl_path), exist_ok=True)

        # Load or create CA
        self.ca_certificate = None
        self.ca_private_key = None
        self.load_or_create_ca()

        print("✅ CA Manager initialized for CertAuth: Vendor Authentication System")

    def load_or_create_ca(self):
        """Load existing CA or create new one"""
        if os.path.exists(self.ca_cert_path) and os.path.exists(self.ca_key_path):
            print("📂 Loading existing Root CA...")
            self.load_ca()
        else:
            print("🏛️ Creating new Root CA for CertAuth: Vendor Authentication System...")
            self.create_root_ca()

    def create_root_ca(self):
        """Create self-signed Root CA certificate"""
        # Generate CA private key
        ca_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )

        # Create CA certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Manufacturing Corporation"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Supply Chain Security"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Manufacturing Corp Root CA"),
        ])

        ca_certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(ca_private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365 * 10))  # 10 years
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=2),
                critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,  # Can sign certificates
                    crl_sign=True,       # Can sign CRLs
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(ca_private_key.public_key()),
                critical=False
            )
            .sign(ca_private_key, hashes.SHA256(), default_backend())
        )

        # Save CA files
        with open(self.ca_cert_path, "wb") as f:
            f.write(ca_certificate.public_bytes(serialization.Encoding.PEM))

        with open(self.ca_key_path, "wb") as f:
            f.write(ca_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        self.ca_certificate = ca_certificate
        self.ca_private_key = ca_private_key

        print(f"✅ Root CA created: {self.ca_cert_path}")

    def load_ca(self):
        """Load existing CA from files"""
        try:
            with open(self.ca_cert_path, "rb") as f:
                self.ca_certificate = x509.load_pem_x509_certificate(f.read(), default_backend())

            with open(self.ca_key_path, "rb") as f:
                self.ca_private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )

            print(f"✅ Root CA loaded: {self.ca_cert_path}")
        except Exception as e:
            print(f"❌ Failed to load CA: {e}")
            raise

    def issue_vendor_certificate(self, vendor_data, public_key_pem, validity_days=365):
        """
        Issue X.509 certificate to vendor for CertAuth: Vendor Authentication System

        Args:
            vendor_data: Dict with vendor info
            public_key_pem: Vendor's public key in PEM format
            validity_days: Certificate validity period

        Returns:
            Dict with certificate info
        """
        if not self.ca_certificate or not self.ca_private_key:
            raise ValueError("CA not initialized")

        # Load vendor's public key
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode(),
            backend=default_backend()
        )

        # Create vendor subject name
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, vendor_data.get('state', 'New York')),
            x509.NameAttribute(NameOID.LOCALITY_NAME, vendor_data.get('city', 'New York')),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, vendor_data['company_name']),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Quality Department"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"{vendor_data['company_name']} Vendor Certificate"),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, vendor_data['email']),
        ])

        # Generate unique serial
        serial_number = x509.random_serial_number()

        # Build certificate
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.ca_certificate.subject)
            .public_key(public_key)
            .serial_number(serial_number)
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=validity_days))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,    # Can sign documents
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,      # Cannot sign certificates
                    crl_sign=False,           # Cannot sign CRLs
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )
            .add_extension(
                x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(public_key),
                critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_private_key.public_key()),
                critical=False
            )
            .sign(self.ca_private_key, hashes.SHA256(), default_backend())
        )

        # Convert to PEM
        certificate_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()

        nvb, nva = _get_cert_validity_utc(certificate)

        cert_info = {
                'serial_number': str(serial_number),
                'vendor_id': vendor_data.get('vendor_id', ''),
                'subject': str(certificate.subject),
                'issuer': str(certificate.issuer),
                'not_valid_before': nvb.isoformat(),
                'not_valid_after': nva.isoformat(),
                'certificate_pem': certificate_pem,
                'fingerprint': self.get_certificate_fingerprint(certificate),
                'status': 'active'
}

        print(f"✅ Certificate issued to {vendor_data['company_name']} (Serial: {serial_number})")
        return cert_info

    def validate_certificate(self, certificate_pem, check_revocation=True):
        """
        Validate certificate for supply chain authentication

        Args:
            certificate_pem: Certificate in PEM format
            check_revocation: Check against CRL

        Returns:
            Tuple (is_valid, reason)
        """
        try:
            # Load certificate
            certificate = x509.load_pem_x509_certificate(
                certificate_pem.encode(),
                default_backend()
            )

            current_time = datetime.now(timezone.utc)
            nvb, nva = _get_cert_validity_utc(certificate)

            if current_time < nvb:
                return False, "Certificate not yet valid"
            if current_time > nva:
                return False, "Certificate expired"

            # 2. Check if issued by our CA
            if certificate.issuer != self.ca_certificate.subject:
                return False, "Certificate not issued by trusted CA"

            # 3. Verify signature using CA's public key
            try:
                self.ca_certificate.public_key().verify(
                    certificate.signature,
                    certificate.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    certificate.signature_hash_algorithm
                )
            except Exception:
                return False, "Invalid certificate signature"

            # 4. Check revocation if enabled
            if check_revocation and self.is_certificate_revoked(certificate):
                return False, "Certificate revoked"

            return True, "Certificate valid"

        except Exception as e:
            return False, f"Validation error: {str(e)}"

    def revoke_certificate(self, serial_number, reason_code=0, reason_text=""):
        """
        Revoke a certificate (add to CRL)

        Reason codes:
            0 = unspecified
            1 = keyCompromise
            2 = CACompromise
            3 = affiliationChanged
            4 = superseded
            5 = cessationOfOperation
            6 = certificateHold
        """
        # Map integer codes to ReasonFlags
        reason_flag_map = {
            0: ReasonFlags.unspecified,
            1: ReasonFlags.key_compromise,
            2: ReasonFlags.ca_compromise,
            3: ReasonFlags.affiliation_changed,
            4: ReasonFlags.superseded,
            5: ReasonFlags.cessation_of_operation,
            6: ReasonFlags.certificate_hold,
        }
        reason_flag = reason_flag_map.get(reason_code, ReasonFlags.unspecified)

        # Load existing CRL or create new
        crl = self.load_crl()
        # print(f"DEBUG: Existing CRL loaded: {crl is not None}")  # Debug

        # Create revoked certificate entry
        revoked_cert = x509.RevokedCertificateBuilder().serial_number(
            int(serial_number)
        ).revocation_date(
            datetime.now(timezone.utc)
        ).add_extension(
            x509.CRLReason(reason_flag),
            critical=False
        ).build(default_backend())

        # print(f"DEBUG: Revoked certificate built for serial {serial_number}")  # Debug

        # Build new CRL
        crl_builder = x509.CertificateRevocationListBuilder()
        crl_builder = crl_builder.issuer_name(self.ca_certificate.subject)
        crl_builder = crl_builder.last_update(datetime.now(timezone.utc))
        crl_builder = crl_builder.next_update(datetime.now(timezone.utc) + timedelta(days=7))

        # Add all revoked certificates (handle both property and method)
        if crl:
            revoked_certs = None
            if hasattr(crl, 'revoked_certificates'):
                revoked_certs = crl.revoked_certificates
            elif hasattr(crl, 'get_revoked_certificates'):
                revoked_certs = crl.get_revoked_certificates()
            if revoked_certs:
                # print(f"DEBUG: Adding {len(revoked_certs)} existing revoked certs")  # Debug
                for cert in revoked_certs:
                    crl_builder = crl_builder.add_revoked_certificate(cert)

        crl_builder = crl_builder.add_revoked_certificate(revoked_cert)

        # Sign CRL
        new_crl = crl_builder.sign(
            private_key=self.ca_private_key,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )

        # Save CRL
        with open(self.crl_path, "wb") as f:
            f.write(new_crl.public_bytes(serialization.Encoding.PEM))
        # print(f"DEBUG: CRL saved to {self.crl_path}")  # Debug

        print(f"⚠️ Certificate {serial_number} revoked. Reason: {reason_text}")
        return True

    def is_certificate_revoked(self, certificate):
        """Check if certificate is in CRL"""
        # print(f"DEBUG: Checking revocation for serial {certificate.serial_number}")  # Debug
        if not os.path.exists(self.crl_path):
            # print("DEBUG: CRL file does not exist")  # Debug
            return False

        try:
            with open(self.crl_path, "rb") as f:
                crl = x509.load_pem_x509_crl(f.read(), default_backend())
                # print(f"DEBUG: CRL loaded from {self.crl_path}")  # Debug

            # Try to get revoked certificates (property or method)
            revoked_certs = None
            if hasattr(crl, 'revoked_certificates'):
                revoked_certs = crl.revoked_certificates
                # print("DEBUG: Using revoked_certificates property")  # Debug
            elif hasattr(crl, 'get_revoked_certificates'):
                revoked_certs = crl.get_revoked_certificates()
                # print("DEBUG: Using get_revoked_certificates method")  # Debug

            if revoked_certs:
                # serials = [r.serial_number for r in revoked_certs]
                # print(f"DEBUG: Revoked serials in CRL: {serials}")  # Debug
                for revoked_cert in revoked_certs:
                    if revoked_cert.serial_number == certificate.serial_number:
                        # print(f"DEBUG: Certificate {certificate.serial_number} found in CRL")  # Debug
                        return True
            else:
                print("DEBUG: No revoked certificates in CRL")  # Debug
            return False
        except Exception as e:
            print(f"⚠️ Error reading CRL: {e}")
            return False

    def load_crl(self):
        """Load Certificate Revocation List"""
        if not os.path.exists(self.crl_path):
            return None

        try:
            with open(self.crl_path, "rb") as f:
                return x509.load_pem_x509_crl(f.read(), default_backend())
        except Exception as e:
            print(f"⚠️ Error loading CRL: {e}")
            return None

    def get_certificate_fingerprint(self, certificate):
        """Get SHA-256 fingerprint of certificate"""
        cert_bytes = certificate.public_bytes(serialization.Encoding.DER)
        digest = hashes.Hash(hashes.SHA256(), default_backend())
        digest.update(cert_bytes)
        fingerprint = digest.finalize()
        return base64.b64encode(fingerprint).decode()

    def get_ca_info(self):
        """Get CA information for display"""
        if not self.ca_certificate:
            return None

        nvb, nva = _get_cert_validity_utc(self.ca_certificate)

        return {
            'subject': str(self.ca_certificate.subject),
            'issuer': str(self.ca_certificate.issuer),
            'serial': str(self.ca_certificate.serial_number),
            'valid_from': nvb.isoformat(),
            'valid_to': nva.isoformat(),
            'fingerprint': self.get_certificate_fingerprint(self.ca_certificate),
            'has_crl': os.path.exists(self.crl_path)
}

# Alternative test function that doesn't import certificate_engine
def test_ca_manager_simple():
    """Simple test without external dependencies"""
    print("\n" + "=" * 60)
    print("TESTING CERTIFICATE AUTHORITY MANAGER")
    print("=" * 60)

    ca = CertificateAuthorityManager()

    # Test CA info
    ca_info = ca.get_ca_info()
    print(f"✅ Root CA Subject: {ca_info['subject']}")
    print(f"✅ Valid Until: {ca_info['valid_to']}")
    print(f"✅ Fingerprint: {ca_info['fingerprint']}")

    # Create a test public key
    from cryptography.hazmat.primitives.asymmetric import rsa
    test_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    test_public_key_pem = test_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    # Test vendor data
    vendor_data = {
        'company_name': 'Test Steel Supplier Inc.',
        'email': 'quality@steelsupplier.com',
        'vendor_id': 'VEND001',
        'city': 'Detroit',
        'state': 'Michigan'
    }

    # Issue certificate
    cert_info = ca.issue_vendor_certificate(vendor_data, test_public_key_pem, 180)
    print(f"✅ Vendor certificate issued: Serial {cert_info['serial_number']}")
    print(f"✅ Valid from: {cert_info['not_valid_before']}")
    print(f"✅ Valid to: {cert_info['not_valid_after']}")

    # Validate certificate
    is_valid, reason = ca.validate_certificate(cert_info['certificate_pem'])
    print(f"✅ Certificate validation: {is_valid} ({reason})")

    print("=" * 60)
    print("✅ CA MANAGER TEST COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    test_ca_manager_simple()