# crypto/certificate_engine.py - FIXED VERSION
"""
CORE CRYPTOGRAPHY ENGINE for CertAuth
"""
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
import base64
import secrets
import string

class CertificateEngine:
    """Main cryptographic engine"""
    
    def __init__(self):
        self.backend = default_backend()
        print("🔐 Crypto Engine Ready")
    
    # 1. KEY GENERATION - FIXED with random passwords
    def generate_key_pair(self, password=None):
        """Generate RSA key pair for vendor with RANDOM password"""
        
        # Generate RANDOM password if not provided
        if password is None:
            # Create strong random password: 12 characters with letters, digits
            alphabet = string.ascii_letters + string.digits
            password = ''.join(secrets.choice(alphabet) for _ in range(12))
        
        # Validate password strength
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters")
        
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=self.backend
        )
        
        # Encrypt private key with UNIQUE password
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(
                password.encode()
            )
        )
        
        # Get public key
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return {
            'private_key': private_pem.decode(),
            'public_key': public_pem.decode(),
            'password': password  # UNIQUE password for each vendor
        }
    
    # 2. SIGN DOCUMENT - FIXED with better error handling
    def sign_document(self, private_key_pem, document_text, password):
        """Sign a document with proper error handling"""
        try:
            # Debug info
            # print(f"🔐 DEBUG: Signing document with password length: {len(password) if password else 0}")
            
            # Load private key
            if password and password.strip():
                private_key = serialization.load_pem_private_key(
                    private_key_pem.encode(),
                    password=password.encode(),
                    backend=self.backend
                )
            else:
                # Try without password (unencrypted key)
                private_key = serialization.load_pem_private_key(
                    private_key_pem.encode(),
                    password=None,
                    backend=self.backend
                )
            
            # Sign
            signature = private_key.sign(
                document_text.encode(),
                padding=padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                algorithm=hashes.SHA256()
            )
            
            return base64.b64encode(signature).decode()
            
        except Exception as e:
            print(f"❌ Signing error: {e}")
            
            # Try with trimmed password (sometimes has whitespace)
            if password:
                try:
                    print("🔄 Trying with trimmed password")
                    private_key = serialization.load_pem_private_key(
                        private_key_pem.encode(),
                        password=password.strip().encode(),
                        backend=self.backend
                    )
                    signature = private_key.sign(
                        document_text.encode(),
                        padding=padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        algorithm=hashes.SHA256()
                    )
                    return base64.b64encode(signature).decode()
                except:
                    pass
            raise
    
    # 3. VERIFY SIGNATURE
    def verify_signature(self, public_key_pem, document_text, signature_b64):
        """Verify document signature"""
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode(),
                backend=self.backend
            )
            
            signature = base64.b64decode(signature_b64)
            
            public_key.verify(
                signature,
                document_text.encode(),
                padding=padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                algorithm=hashes.SHA256()
            )
            return True
        except:
            return False

# Test the fixed version
if __name__ == "__main__":
    print("\n" + "="*60)
    print("TESTING FIXED CERTIFICATE ENGINE")
    print("="*60)
    
    engine = CertificateEngine()
    
    # Test 1: Generate key pair with random password
    print("\n1. Generating key pair with RANDOM password...")
    keys1 = engine.generate_key_pair()
    print(f"✅ Key pair 1 generated")
    print(f"   Password: {keys1['password']}")
    print(f"   Password length: {len(keys1['password'])}")
    
    # Test 2: Generate another key pair (should have DIFFERENT password)
    print("\n2. Generating second key pair...")
    keys2 = engine.generate_key_pair()
    print(f"✅ Key pair 2 generated")
    print(f"   Password: {keys2['password']}")
    print(f"   Password length: {len(keys2['password'])}")
    
    # Test 3: Verify passwords are different
    if keys1['password'] != keys2['password']:
        print("✅ PASS: Passwords are different (secure!)")
    else:
        print("❌ FAIL: Passwords are the same (security risk!)")
    
    # Test 4: Sign and verify document
    print("\n3. Testing document signing...")
    test_document = "Quality Certificate: Steel Grade A, Batch #12345"
    signature = engine.sign_document(
        keys1['private_key'],
        test_document,
        keys1['password']
    )
    print(f"✅ Document signed")
    print(f"   Signature: {signature[:30]}...")
    
    # Test 5: Verify signature
    is_valid = engine.verify_signature(
        keys1['public_key'],
        test_document,
        signature
    )
    print(f"✅ Signature verification: {is_valid}")
    
    # Test 6: Try wrong password (should fail)
    print("\n4. Testing wrong password (should fail)...")
    try:
        engine.sign_document(
            keys1['private_key'],
            test_document,
            "wrongpassword123"
        )
        print("❌ FAIL: Wrong password should not work!")
    except:
        print("✅ PASS: Wrong password correctly rejected")
    
    print("\n" + "="*60)
    print("✅ FIXED CERTIFICATE ENGINE TEST COMPLETE")
    print("="*60)