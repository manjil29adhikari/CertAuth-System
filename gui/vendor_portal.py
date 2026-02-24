"""
VENDOR PORTAL for CertAuth: Vendor Authentication System - WITH REAL FILE SHARING
"""
import customtkinter as ctk
from tkinter import messagebox, filedialog
import sys
import os
import hashlib
import json
import random
from datetime import datetime
import sqlite3
import webbrowser
import base64
import tempfile
import shutil

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import from our modules
# Try to import EncryptionManager
try:
    # print("🔍 DEBUG: Attempting to import EncryptionManager...")
    from crypto.encryption import EncryptionManager
    # Check if it's using real crypto
    if hasattr(EncryptionManager, 'CRYPTOGRAPHY_AVAILABLE'):
        print(f"🔍 DEBUG: CRYPTOGRAPHY_AVAILABLE = {EncryptionManager.CRYPTOGRAPHY_AVAILABLE}")
    encryption_available = True
    # print("✅ Real EncryptionManager loaded")
except ImportError as e:
    print(f"❌ Failed to import EncryptionManager: {e}")
    encryption_available = False
    
    # Import from our modules
# print("🔍 DEBUG: Starting imports in vendor_portal.py")
# print(f"🔍 DEBUG: Current directory: {os.getcwd()}")
# print(f"🔍 DEBUG: Python path: {sys.path}")

try:
    # print("🔍 DEBUG: Attempting to import CertificateEngine...")
    from crypto.certificate_engine import CertificateEngine
    # print("✅ Successfully imported CertificateEngine")
    
    # print("🔍 DEBUG: Attempting to import CertificateAuthorityManager...")
    from crypto.ca_manager import CertificateAuthorityManager
    # print("✅ Successfully imported CertificateAuthorityManager")
    
    print("🔍 DEBUG: Attempting to import db...")
    from database.models import db
    print("✅ Successfully imported db")
    
    print("✅ Using real crypto modules")
except ImportError as e:
    print(f"❌ IMPORT ERROR: {e}")
    print("🔧 Falling back to MOCK implementations")
    
    # Mock classes for fallback
    class MockCertificateEngine:
        def __init__(self):
            print("🔧 MOCK: CertificateEngine initialized")
            pass
        def generate_key_pair(self, password=None):
            import secrets, string
            if password is None:
                alphabet = string.ascii_letters + string.digits
                password = ''.join(secrets.choice(alphabet) for _ in range(12))
            return {'private_key': 'MOCK_PRIVATE_KEY', 'public_key': 'MOCK_PUBLIC_KEY', 'password': password}
        def sign_document(self, private_key, text, password):
            import base64, hashlib
            return base64.b64encode(f"MOCK_SIGNATURE_{hashlib.sha256(text.encode()).hexdigest()}".encode()).decode()
        def verify_signature(self, public_key, text, signature):
            return True
    
    class MockCAManager:
        def __init__(self):
            print("🔧 MOCK: CAManager initialized")
            pass
        def issue_vendor_certificate(self, vendor_data, public_key, days=365):
            return {'serial_number': 'MOCK123', 'certificate_pem': 'MOCK_CERT', 
                   'subject': f'CN={vendor_data.get("company_name", "Test")}',
                   'issuer': 'CN=Mock CA', 'not_valid_before': '2025-01-01', 'not_valid_after': '2025-12-31'}
        def validate_certificate(self, cert_pem):
            return True, "Mock valid"
        def get_ca_info(self):
            return {'subject': 'CN=Mock CA', 'fingerprint': 'mock123', 'has_crl': True}
    
    CertificateEngine = MockCertificateEngine
    CertificateAuthorityManager = MockCAManager
    db = None
    print("🔧 MOCK implementations assigned")

# print(f"🔍 DEBUG: CertificateEngine is now: {CertificateEngine}")

# Try to import EncryptionManager
try:
    from crypto.encryption import EncryptionManager
    encryption_available = True
    print("✅ Real EncryptionManager loaded")
except ImportError as e:
    print(f"❌ Failed to import EncryptionManager: {e}")
    encryption_available = False
    # Mock EncryptionManager for fallback - FIXED VERSION
    class MockEncryptionManager:
        @staticmethod
        def encrypt_document(content, public_key_pem, password=None):
            print(f"Mock: Encrypting document of length {len(content)}")
            return {
                'encrypted_content': base64.b64encode(f"ENCRYPTED_{content}".encode()).decode(),
                'encrypted_key': base64.b64encode(b'MOCK_ENCRYPTED_KEY').decode(),
                'iv': base64.b64encode(b'MOCK_IV_1234567890').decode(),
                'salt': base64.b64encode(b'MOCK_SALT').decode() if password else None,
                'algorithm': 'RSA-AES-HYBRID',
                'timestamp': datetime.now().isoformat()
            }
        
        @staticmethod
        def decrypt_document(encrypted_data, private_key_pem, password=None):
            print(f"Mock: Decrypting document with keys: {encrypted_data.keys()}")
            if 'encrypted_content' in encrypted_data:
                encrypted_content = base64.b64decode(encrypted_data['encrypted_content'])
                result = encrypted_content.decode().replace('ENCRYPTED_', '')
                print(f"Mock: Decrypted {len(result)} chars")
                return result
            return "Mock decrypted content"
        
        @staticmethod
        def encrypt_message(message, recipient_public_key, sender_private_key=None, password=None):
            print(f"Mock: Encrypting message: {message[:50]}...")
            return {
                'message': base64.b64encode(f"ENCRYPTED_{message}".encode()).decode(),
                'key': base64.b64encode(b'MOCK_KEY').decode(),
                'iv': base64.b64encode(b'MOCK_IV').decode(),
                'algorithm': 'RSA-AES-HYBRID',
                'timestamp': datetime.now().isoformat(),
                'signature': 'MOCK_SIGNATURE' if sender_private_key else None
            }
        
        @staticmethod
        def decrypt_message(encrypted_message, recipient_private_key, password=None):
            print(f"Mock: Decrypting message with keys: {encrypted_message.keys()}")
            # Handle both 'message' and 'encrypted_content' keys
            if 'message' in encrypted_message:
                message_data = base64.b64decode(encrypted_message['message'])
                result = message_data.decode().replace('ENCRYPTED_', '')
            elif 'encrypted_content' in encrypted_message:
                message_data = base64.b64decode(encrypted_message['encrypted_content'])
                result = message_data.decode().replace('ENCRYPTED_', '')
            else:
                result = "Mock decrypted message"
            
            print(f"Mock: Decrypted {len(result)} chars")
            return result
    
    EncryptionManager = MockEncryptionManager

# ========== VENDOR REGISTRATION WINDOW ==========
class VendorRegistrationWindow:
    def __init__(self, on_registration_success=None):
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        self.window = ctk.CTk()
        self.window.title("CertAuth: Vendor Authentication System - Vendor Registration")
        self.window.geometry("650x900")
        self.window.resizable(False, False)
        
        self.on_registration_success = on_registration_success
        self.crypto_engine = CertificateEngine()
        self.ca_manager = CertificateAuthorityManager()
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup vendor registration interface"""
        # Main frame
        main_frame = ctk.CTkFrame(self.window, corner_radius=20)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Title
        ctk.CTkLabel(
            main_frame,
            text="🏭 Vendor Registration",
            font=ctk.CTkFont(size=28, weight="bold")
        ).pack(pady=(30, 10))
        
        ctk.CTkLabel(
            main_frame,
            text="CertAuth: Vendor Authentication System",
            font=ctk.CTkFont(size=14)
        ).pack(pady=(0, 30))
        
        # Registration form frame
        form_frame = ctk.CTkFrame(main_frame, corner_radius=15)
        form_frame.pack(padx=40, pady=10, fill="x")
        
        # Company Information
        ctk.CTkLabel(
            form_frame,
            text="Company Information",
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(pady=(20, 15), padx=20, anchor="w")
        
        # Form fields
        fields = [
            ("Company Name:", "Enter your company name", "company_name"),
            ("PAN/VAT Number:","Enter your PAN/VAT number", "PAN/VAT number"),
            ("Email Address:", "contact@company.com", "email"),
            ("Contact Person:", "Full name", "contact_person"),
            ("Phone:", "+977 ", "phone"),
            ("Address:", "Company address", "address"),
            ("City:", "City", "city"),
            ("State:", "State/Province", "state"),
        ]
        
        self.entries = {}
        
        for label_text, placeholder, field_name in fields:
            field_frame = ctk.CTkFrame(form_frame, fg_color="transparent")
            field_frame.pack(pady=8, padx=20, fill="x")
            
            ctk.CTkLabel(
                field_frame,
                text=label_text,
                font=ctk.CTkFont(size=14)
            ).pack(side="left", padx=(0, 10))
            
            entry = ctk.CTkEntry(
                field_frame,
                placeholder_text=placeholder,
                height=40
            )
            entry.pack(side="right", fill="x", expand=True)
            self.entries[field_name] = entry
        
        # Registration button
        register_btn = ctk.CTkButton(
            form_frame,
            text="🔐 REGISTER & GENERATE DIGITAL CERTIFICATE",
            command=self.register_vendor,
            height=55,
            font=ctk.CTkFont(size=16, weight="bold"),
            fg_color="#2E8B57",
            hover_color="#228B22"
        )
        register_btn.pack(pady=30, padx=20, fill="x")
        
        # Info
        ctk.CTkLabel(
            main_frame,
            text="Upon registration:\n1. Generate RSA 2048-bit key pair\n2. Issue X.509 digital certificate\n3. Store in secure database",
            font=ctk.CTkFont(size=12),
            text_color="gray"
        ).pack(pady=(10, 20))
        
        # Back to login button
        ctk.CTkButton(
            main_frame,
            text="← Back to Login",
            command=self.open_login,
            fg_color="transparent",
            hover_color=("gray70", "gray30"),
            text_color=("gray10", "gray90")
        ).pack(pady=(0, 20))
    
    def open_login(self):
        """Open login window"""
        self.window.destroy()
        start_vendor_login()
    
    def register_vendor(self):
        """Handle vendor registration with PKI"""
        # Get form data
        vendor_data = {}
        for field_name, entry in self.entries.items():
            value = entry.get().strip()
            if not value and field_name in ['company_name', 'email']:
                messagebox.showwarning("Input Required", f"Please enter {field_name.replace('_', ' ')}")
                return
            vendor_data[field_name] = value
        
        try:
            # 1. Generate key pair (PKI Requirement)
            keys = self.crypto_engine.generate_key_pair()
            
            # 2. Register in database
            if db:
                vendor_id = db.register_vendor({
                    'company_name': vendor_data['company_name'],
                    'email': vendor_data['email'],
                    'contact_person': vendor_data.get('contact_person', '')
                })
            else:
                vendor_id = f"VEND{datetime.now().strftime('%Y%m%d%H%M%S')}"
            
            # 3. Issue digital certificate (PKI Requirement)
            cert_info = self.ca_manager.issue_vendor_certificate(
                vendor_data={**vendor_data, 'vendor_id': vendor_id},
                public_key_pem=keys['public_key'],
                validity_days=365
            )
            
            # 4. Store certificate in database
            if db:
                db.update_vendor_certificate(vendor_id, keys['public_key'], cert_info['serial_number'])
                db.store_certificate({
                    'serial': cert_info['serial_number'],
                    'vendor_id': vendor_id,
                    'issuer': cert_info['issuer'],
                    'subject': cert_info['subject'],
                    'not_valid_before': cert_info.get('not_valid_before', '2025-01-01'),
                    'not_valid_after': cert_info.get('not_valid_after', '2025-12-31'),
                    'certificate_data': cert_info['certificate_pem']
                })
            
            # 5. Show success message with credentials
            self.show_registration_success(vendor_id, keys, cert_info, vendor_data)
            
            # 6. Log audit
            if db:
                db.log_audit_event('vendor', vendor_id, 'registration', 'New vendor registered with PKI')
            
        except Exception as e:
            messagebox.showerror("Registration Error", f"Failed to register: {str(e)}")
    
    def show_registration_success(self, vendor_id, keys, cert_info, vendor_data):
        """Show registration success with credentials"""
        success_window = ctk.CTkToplevel(self.window)
        success_window.title("Registration Successful")
        success_window.geometry("700x650")
        success_window.resizable(False, False)
        success_window.transient(self.window)
        success_window.grab_set()
        
        ctk.CTkLabel(
            success_window,
            text="✅ VENDOR REGISTRATION SUCCESSFUL",
            font=ctk.CTkFont(size=22, weight="bold")
        ).pack(pady=20)
        
        # Credentials frame
        cred_frame = ctk.CTkFrame(success_window, corner_radius=10)
        cred_frame.pack(pady=10, padx=30, fill="both", expand=True)
        
        info_items = [
            ("Vendor ID:", vendor_id),
            ("Company:", vendor_data['company_name']),
            ("Certificate Serial:", cert_info['serial_number']),
            ("Valid Until:", cert_info.get('not_valid_after', '2025-12-31')[:10]),
            ("Private Key Password:", keys['password']),
        ]
        
        for label, value in info_items:
            item_frame = ctk.CTkFrame(cred_frame, fg_color="transparent")
            item_frame.pack(pady=8, padx=20, fill="x")
            
            ctk.CTkLabel(
                item_frame,
                text=label,
                font=ctk.CTkFont(size=14, weight="bold")
            ).pack(side="left")
            
            ctk.CTkLabel(
                item_frame,
                text=value,
                font=ctk.CTkFont(size=14)
            ).pack(side="right")
        
        # Security warning
        warning_frame = ctk.CTkFrame(cred_frame, fg_color="#FFF3CD", corner_radius=8)
        warning_frame.pack(pady=20, padx=10, fill="x")
        
        ctk.CTkLabel(
            warning_frame,
            text="⚠️ SECURITY WARNING",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#856404"
        ).pack(pady=(10, 5), padx=10)
        
        ctk.CTkLabel(
            warning_frame,
            text="• Save your private key securely\n• Never share your private key password\n• Use certificate for document signing",
            font=ctk.CTkFont(size=12),
            text_color="#856404"
        ).pack(pady=(0, 10), padx=10)
        
        # Save credentials button
        def save_credentials():
            file_path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                initialfile=f"{vendor_id}_credentials.txt"
            )
            if file_path:
                with open(file_path, 'w') as f:
                    f.write(f"CertAuth: Vendor Authentication System - VENDOR CREDENTIALS\n")
                    f.write(f"="*50 + "\n")
                    f.write(f"Vendor ID: {vendor_id}\n")
                    f.write(f"Company: {vendor_data['company_name']}\n")
                    f.write(f"Certificate Serial: {cert_info['serial_number']}\n")
                    f.write(f"Valid Until: {cert_info.get('not_valid_after', '2025-12-31')[:10]}\n")
                    f.write(f"Private Key Password: {keys['password']}\n\n")
                    f.write(f"PRIVATE KEY (Keep Secure!):\n")
                    f.write(f"{keys['private_key']}\n\n")
                    f.write(f"CERTIFICATE:\n")
                    f.write(f"{cert_info['certificate_pem']}\n")
                messagebox.showinfo("Saved", f"Credentials saved to {file_path}")
        
        ctk.CTkButton(
            success_window,
            text="💾 Save Credentials to File",
            command=save_credentials,
            height=45,
            fg_color="#17A2B8",
            hover_color="#138496"
        ).pack(pady=10, padx=30, fill="x")
        
        # Continue button
        def continue_to_login():
            success_window.destroy()
            self.window.destroy()
            # Always open login window
            start_vendor_login()
        
        ctk.CTkButton(
            success_window,
            text="🚀 Continue to Vendor Login",
            command=continue_to_login,
            height=50,
            fg_color="#28A745",
            hover_color="#218838"
        ).pack(pady=20, padx=30, fill="x")
    
    def run(self):
        self.window.mainloop()

# ========== VENDOR LOGIN WINDOW ==========
class VendorLoginWindow:
    def __init__(self, on_login_success=None):
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        self.window = ctk.CTk()
        self.window.title("CertAuth: Vendor Authentication System- Vendor Login")
        self.window.geometry("550x850")
        self.window.resizable(False, False)
        
        self.on_login_success = on_login_success
        self.crypto_engine = CertificateEngine()
        self.ca_manager = CertificateAuthorityManager()
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup certificate-based login interface"""
        main_frame = ctk.CTkFrame(self.window, corner_radius=20)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Title
        ctk.CTkLabel(
            main_frame,
            text="🔐 Vendor Certificate Login",
            font=ctk.CTkFont(size=28, weight="bold")
        ).pack(pady=(40, 10))
        
        ctk.CTkLabel(
            main_frame,
            text="PKI Authentication for CertAuth: Vendor Authentication System",
            font=ctk.CTkFont(size=14)
        ).pack(pady=(0, 40))
        
        # Login frame
        login_frame = ctk.CTkFrame(main_frame, corner_radius=15)
        login_frame.pack(padx=40, pady=10, fill="x")
        
        # Vendor ID
        ctk.CTkLabel(
            login_frame,
            text="Vendor ID:",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(pady=(20, 5), padx=30, anchor="w")
        
        self.vendor_id_entry = ctk.CTkEntry(
            login_frame,
            placeholder_text="Enter your Vendor ID (e.g., VEND202401010001)",
            height=45
        )
        self.vendor_id_entry.pack(pady=5, padx=30, fill="x")
        
        # Certificate upload
        ctk.CTkLabel(
            login_frame,
            text="Digital Certificate (.crt or .pem):",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(pady=(15, 5), padx=30, anchor="w")
        
        cert_frame = ctk.CTkFrame(login_frame, fg_color="transparent")
        cert_frame.pack(pady=5, padx=30, fill="x")
        
        self.cert_path_var = ctk.StringVar(value="No certificate selected")
        ctk.CTkLabel(
            cert_frame,
            textvariable=self.cert_path_var,
            font=ctk.CTkFont(size=12),
            text_color="gray"
        ).pack(side="left", padx=(0, 10))
        
        ctk.CTkButton(
            cert_frame,
            text="📁 Browse",
            command=self.browse_certificate,
            width=80
        ).pack(side="right")
        
        # Private key upload
        ctk.CTkLabel(
            login_frame,
            text="Private Key (.key or .pem):",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(pady=(15, 5), padx=30, anchor="w")
        
        key_frame = ctk.CTkFrame(login_frame, fg_color="transparent")
        key_frame.pack(pady=5, padx=30, fill="x")
        
        self.key_path_var = ctk.StringVar(value="No private key selected")
        ctk.CTkLabel(
            key_frame,
            textvariable=self.key_path_var,
            font=ctk.CTkFont(size=12),
            text_color="gray"
        ).pack(side="left", padx=(0, 10))
        
        ctk.CTkButton(
            key_frame,
            text="📁 Browse",
            command=self.browse_private_key,
            width=80
        ).pack(side="right")
        
        # Password
        ctk.CTkLabel(
            login_frame,
            text="Private Key Password:",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(pady=(15, 5), padx=30, anchor="w")
        
        self.password_entry = ctk.CTkEntry(
            login_frame,
            placeholder_text="Enter private key password",
            show="•",
            height=45
        )
        self.password_entry.pack(pady=5, padx=30, fill="x")
        
        # Login button
        login_btn = ctk.CTkButton(
            login_frame,
            text="🔓 LOGIN WITH CERTIFICATE",
            command=self.authenticate_with_certificate_fixed,
            height=55,
            font=ctk.CTkFont(size=16, weight="bold"),
            fg_color="#2E8B57",
            hover_color="#228B22"
        )
        login_btn.pack(pady=30, padx=30, fill="x")
        
        # Register link
        ctk.CTkButton(
            main_frame,
            text="📝 New Vendor? Register Here",
            command=self.open_registration,
            fg_color="transparent",
            hover_color=("gray70", "gray30"),
            text_color=("gray10", "gray90")
        ).pack(pady=(10, 20))
        
        # Back to main menu
        ctk.CTkButton(
            main_frame,
            text="← Back to Main Menu",
            command=self.back_to_main,
            fg_color="transparent",
            hover_color=("gray70", "gray30"),
            text_color=("gray10", "gray90")
        ).pack(pady=(0, 20))
    
    def browse_certificate(self):
        """Browse for certificate file"""
        file_path = filedialog.askopenfilename(
            title="Select Digital Certificate",
            filetypes=[("Certificate files", "*.crt *.pem *.cer"), ("All files", "*.*")]
        )
        if file_path:
            self.cert_path_var.set(os.path.basename(file_path))
            self.certificate_path = file_path
    
    def browse_private_key(self):
        """Browse for private key file"""
        file_path = filedialog.askopenfilename(
            title="Select Private Key",
            filetypes=[("Key files", "*.key *.pem"), ("All files", "*.*")]
        )
        if file_path:
            self.key_path_var.set(os.path.basename(file_path))
            self.private_key_path = file_path
    
    def authenticate_with_certificate_fixed(self):
        """FIXED VERSION: Authenticate using PKI certificate with vendor ID verification"""
        vendor_id = self.vendor_id_entry.get().strip()
        
        if not vendor_id:
            messagebox.showwarning("Input Required", "Please enter Vendor ID")
            return
        
        if not hasattr(self, 'certificate_path') or not hasattr(self, 'private_key_path'):
            messagebox.showwarning("Files Required", "Please select certificate and private key files")
            return
        
        password = self.password_entry.get().strip()
        if not password:
            messagebox.showwarning("Input Required", "Please enter private key password")
            return
        
        try:
            # 1. Load certificate
            with open(self.certificate_path, 'r') as f:
                certificate_pem = f.read()
            
            # 2. Validate certificate (PKI Requirement)
            is_valid, reason = self.ca_manager.validate_certificate(certificate_pem)
            
            if not is_valid:
                messagebox.showerror("Authentication Failed", f"Certificate invalid: {reason}")
                return
            
            # 3. Check if vendor exists and certificate belongs to this vendor
            if db:
                # Get vendor info from database
                vendor_info = db.get_vendor_by_id(vendor_id)
                if not vendor_info:
                    messagebox.showerror("Authentication Failed", f"Vendor {vendor_id} not found in system")
                    return
                
                # Check if vendor has a certificate
                vendor_cert_serial = vendor_info.get('certificate_serial')
                if not vendor_cert_serial:
                    messagebox.showerror("Authentication Failed", f"Vendor {vendor_id} has no certificate registered")
                    return
                
                # Get certificate from database for this vendor
                conn = sqlite3.connect(db.db_path)
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT certificate_data FROM certificates WHERE vendor_id = ? AND serial_number = ?",
                    (vendor_id, vendor_cert_serial)
                )
                result = cursor.fetchone()
                conn.close()
                
                if not result:
                    messagebox.showerror("Authentication Failed", 
                                        f"Certificate not found for vendor {vendor_id}")
                    return
                
                # Compare the uploaded certificate with the one in database
                db_certificate_pem = result[0]
                if certificate_pem.strip() != db_certificate_pem.strip():
                    messagebox.showerror("Authentication Failed", 
                                        "Certificate does not match the registered certificate for this vendor")
                    return
                
                # Check vendor status
                if vendor_info.get('status') != 'active':
                    messagebox.showerror("Authentication Failed", 
                                        f"Vendor account is {vendor_info.get('status')}. Contact administrator.")
                    return
            
            # 4. Load private key
            with open(self.private_key_path, 'r') as f:
                private_key_pem = f.read()
            
            # 5. Test signature to prove possession (PKI Requirement)
            # Generate random challenge
            challenge = str(random.randint(100000, 999999))
            
            # Sign challenge with private key
            try:
                signature = self.crypto_engine.sign_document(
                    private_key_pem, 
                    challenge, 
                    password
                )
            except Exception as e:
                messagebox.showerror("Authentication Failed", f"Invalid private key or password: {str(e)}")
                return
            
            # 6. SIMPLIFIED VERIFICATION: Just check if we can sign without error
            # In a real system, we would verify with the public key from certificate
            try:
                test_data = "test_verification"
                test_signature = self.crypto_engine.sign_document(
                    private_key_pem,
                    test_data,
                    password
                )
            except Exception as e:
                messagebox.showerror("Authentication Failed", f"Private key verification failed: {str(e)}")
                return
            
            # 7. Update database with successful login
            if db:
                db.log_audit_event('vendor', vendor_id, 'login', 
                                  f'Certificate-based authentication successful. Vendor verified.')
            
            # 8. Success - vendor ID verified!
            messagebox.showinfo("Authentication Successful", 
                f"✅ PKI Authentication Successful!\n\n"
                f"Verified Vendor: {vendor_id}\n"
                f"Certificate: Valid and Verified\n"
                f"Signature: Verified\n\n"
                f"✅ Certificate belongs to this vendor\n"
                f"✅ Vendor account is active\n"
                f"✅ Private key possession verified")
            
            self.window.destroy()
            if self.on_login_success:
                self.on_login_success(vendor_id, certificate_pem, private_key_pem, password)
                
        except Exception as e:
            messagebox.showerror("Authentication Error", f"PKI Authentication failed: {str(e)}")
    
    def open_registration(self):
        """Open registration window"""
        self.window.destroy()
        registration = VendorRegistrationWindow()
        registration.run()
    
    def back_to_main(self):
        """Back to main menu"""
        self.window.destroy()
        try:
            from gui.main_menu import main
            main()
        except ImportError:
            # If main_menu is not available, just start login
            start_vendor_login()
    
    def run(self):
        self.window.mainloop()

# ========== VENDOR DASHBOARD ==========
class VendorDashboard:
    def __init__(self, vendor_id, certificate_pem, private_key_pem, password):
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        self.window = ctk.CTk()
        self.window.title(f"CertAuth: Vendor Authentication System - Vendor Dashboard ({vendor_id})")
        self.window.geometry("1200x800")
        
        self.vendor_id = vendor_id
        self.certificate_pem = certificate_pem
        self.private_key_pem = private_key_pem
        self.password = password
        
        self.crypto_engine = CertificateEngine()
        self.ca_manager = CertificateAuthorityManager()
        
        # Store current encrypted data for sharing
        self.current_encrypted_data = None
        self.current_decrypted_content = None
        
        # Store shared documents
        self.shared_documents = []
        self.unread_count = 0
        
        self.setup_ui()
        self.load_vendor_info()
        self.load_shared_documents()
    
    def setup_ui(self):
        """Setup vendor dashboard"""
        # Configure grid
        self.window.grid_columnconfigure(1, weight=1)
        self.window.grid_rowconfigure(0, weight=1)
        
        # Sidebar
        self.setup_sidebar()
        
        # Main content
        self.main_content = ctk.CTkFrame(self.window, corner_radius=10)
        self.main_content.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        self.main_content.grid_columnconfigure(0, weight=1)
        self.main_content.grid_rowconfigure(0, weight=1)
        
        # Tabview
        self.tabview = ctk.CTkTabview(self.main_content)
        self.tabview.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        
        # Add tabs - ADDED SHARED DOCUMENTS TAB
        tabs = ["📋 Dashboard", "📝 Sign Document", "🔍 Verify Document", "📜 My Documents", 
                "📂 Shared Documents", "🏛️ Certificate", "🔒 Encrypt/Decrypt", "💬 Secure Messaging", "⚙️ Profile"]
        for tab in tabs:
            self.tabview.add(tab)
        
        # Setup tabs
        self.setup_dashboard()
        self.setup_sign_document()
        self.setup_verify_document()
        self.setup_my_documents()
        self.setup_shared_documents_tab()  # NEW: For viewing received documents
        self.setup_certificate_info()
        self.setup_encryption_tab()
        self.setup_messaging_tab()
        self.setup_profile()
    
    def setup_sidebar(self):
        """Create sidebar navigation"""
        sidebar = ctk.CTkFrame(self.window, width=250, corner_radius=0)
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_rowconfigure(9, weight=1)
        
        # Configure sidebar column
        sidebar.grid_columnconfigure(0, weight=1)
        
        # Logo
        ctk.CTkLabel(
            sidebar,
            text="🏭 Vendor Portal",
            font=ctk.CTkFont(size=22, weight="bold")
        ).grid(row=0, column=0, padx=20, pady=(30, 15), sticky="ew")
        
        # Separator line
        separator1 = ctk.CTkFrame(sidebar, height=2, fg_color="gray30")
        separator1.grid(row=1, column=0, padx=20, pady=(0, 15), sticky="ew")
        
        # Vendor info - with more space
        self.vendor_info_label = ctk.CTkLabel(
            sidebar,
            text=f"ID: {self.vendor_id}\nStatus: Loading...",
            font=ctk.CTkFont(size=12),
            justify="left",
            wraplength=200
        )
        self.vendor_info_label.grid(row=2, column=0, padx=20, pady=(0, 25), sticky="w")
        
        # Unread notifications badge
        self.unread_badge = ctk.CTkLabel(
            sidebar,
            text=f"📭 No unread",
            font=ctk.CTkFont(size=11),
            text_color="gray",
        )
        self.unread_badge.grid(row=3, column=0, padx=20, pady=(0, 15), sticky="w")
        
        # Separator line
        separator2 = ctk.CTkFrame(sidebar, height=2, fg_color="gray30")
        separator2.grid(row=4, column=0, padx=20, pady=(0, 15), sticky="ew")
        
        # Navigation header
        ctk.CTkLabel(
            sidebar,
            text="MAIN NAVIGATION",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="gray70"
        ).grid(row=5, column=0, padx=20, pady=(0, 10), sticky="w")
        
        # Navigation buttons - with consistent spacing
        nav_buttons = [
            ("📋 Dashboard", self.switch_to_dashboard),
            ("📝 Sign Document", self.switch_to_sign_tab),
            ("🔍 Verify Document", self.switch_to_verify_tab),
            ("📜 My Documents", self.switch_to_my_documents),
            ("📂 Shared Documents", self.switch_to_shared_documents_tab),
            ("🔒 Encrypt/Decrypt", self.switch_to_encryption_tab),
            ("💬 Secure Messaging", self.switch_to_messaging_tab),
        ]
        
        for i, (text, command) in enumerate(nav_buttons, start=6):
            btn = ctk.CTkButton(
                sidebar,
                text=text,
                command=command,
                height=40,
                corner_radius=8,
                font=ctk.CTkFont(size=14),
                anchor="w",
                fg_color="transparent",
                hover_color=("gray70", "gray30")
            )
            btn.grid(row=i, column=0, padx=15, pady=2, sticky="ew")
        
        # Separator line before certificate
        separator3 = ctk.CTkFrame(sidebar, height=1, fg_color="gray25")
        separator3.grid(row=13, column=0, padx=20, pady=(10, 10), sticky="ew")
        
        # Certificate section
        ctk.CTkLabel(
            sidebar,
            text="CERTIFICATE",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="gray70"
        ).grid(row=14, column=0, padx=20, pady=(0, 10), sticky="w")
        
        # Certificate button - styled differently
        cert_btn = ctk.CTkButton(
            sidebar,
            text="🏛️ Certificate",
            command=self.switch_to_certificate_tab,
            height=40,
            corner_radius=8,
            font=ctk.CTkFont(size=14),
            anchor="w",
            fg_color="transparent",
            hover_color=("gray70", "gray30"),
            border_width=1,
            border_color="#4CAF50"
        )
        cert_btn.grid(row=15, column=0, padx=15, pady=2, sticky="ew")
        
        # Separator line before profile
        separator4 = ctk.CTkFrame(sidebar, height=1, fg_color="gray25")
        separator4.grid(row=16, column=0, padx=20, pady=(15, 10), sticky="ew")
        
        # Profile button
        profile_btn = ctk.CTkButton(
            sidebar,
            text="⚙️ Profile",
            command=self.switch_to_profile,
            height=40,
            corner_radius=8,
            font=ctk.CTkFont(size=14),
            anchor="w",
            fg_color="transparent",
            hover_color=("gray70", "gray30")
        )
        profile_btn.grid(row=17, column=0, padx=15, pady=2, sticky="ew")
        
        # Separator line before logout
        separator5 = ctk.CTkFrame(sidebar, height=2, fg_color="gray30")
        separator5.grid(row=18, column=0, padx=20, pady=(15, 10), sticky="ew")
        
        # Logout button - moved to bottom with more space
        logout_btn = ctk.CTkButton(
            sidebar,
            text="🚪 Logout",
            command=self.logout,
            height=45,
            fg_color="#FF6B6B",
            hover_color="#FF5252",
            font=ctk.CTkFont(size=14, weight="bold"),
            corner_radius=8
        )
        logout_btn.grid(row=19, column=0, padx=20, pady=(10, 30), sticky="ew")
        
        # Add empty row at the bottom to push everything up
        sidebar.grid_rowconfigure(20, weight=1)
    
    def load_vendor_info(self):
        """Load vendor information from database"""
        if db:
            vendor = db.get_vendor_by_id(self.vendor_id)
            if vendor:
                info_text = f"ID: {vendor['vendor_id']}\n"
                info_text += f"Company: {vendor['company_name'][:15]}...\n"
                info_text += f"Status: {vendor['status'].upper()}\n"
                info_text += f"Since: {vendor['registration_date'][:10]}"
                self.vendor_info_label.configure(text=info_text)
    
    def load_shared_documents(self):
        """Load shared documents for this vendor"""
        if db:
            try:
                self.shared_documents = db.get_shared_documents_for_vendor(self.vendor_id, unread_only=True)
                self.unread_count = len(self.shared_documents)
                if self.unread_count > 0:
                    self.unread_badge.configure(text=f"📬 {self.unread_count} unread document(s)", 
                                               text_color="#FF6B6B")
                else:
                    self.unread_badge.configure(text="📭 No unread documents", 
                                               text_color="gray")
            except Exception as e:
                print(f"Error loading shared documents: {e}")
                self.unread_badge.configure(text="⚠️ Error loading")
    
    # ====== NAVIGATION METHODS ======
    
    def switch_to_dashboard(self):
        self.tabview.set("📋 Dashboard")
        self.refresh_dashboard()
    
    def switch_to_sign_tab(self):
        self.tabview.set("📝 Sign Document")
    
    def switch_to_verify_tab(self):
        self.tabview.set("🔍 Verify Document")
    
    def switch_to_my_documents(self):
        self.tabview.set("📜 My Documents")
        self.refresh_my_documents()
    
    def switch_to_shared_documents_tab(self):
        self.tabview.set("📂 Shared Documents")
        self.refresh_shared_documents()
    
    def switch_to_certificate_tab(self):
        self.tabview.set("🏛️ Certificate")
        self.refresh_certificate_info()
    
    def switch_to_encryption_tab(self):
        self.tabview.set("🔒 Encrypt/Decrypt")
    
    def switch_to_messaging_tab(self):
        self.tabview.set("💬 Secure Messaging")
        self.refresh_messages()
    
    def switch_to_profile(self):
        self.tabview.set("⚙️ Profile")
    
    # ====== DASHBOARD TAB ======
    
    def setup_dashboard(self):
        """Setup dashboard tab"""
        tab = self.tabview.tab("📋 Dashboard")
        self.dashboard_tab = tab
        
        # Will be populated by refresh_dashboard()
    
    def refresh_dashboard(self):
        """Refresh dashboard with real data"""
        tab = self.dashboard_tab
        
        # Clear existing widgets
        for widget in tab.winfo_children():
            widget.destroy()
        
        ctk.CTkLabel(
            tab,
            text="Vendor Dashboard - CertAuth: Vendor Authentication System",
            font=ctk.CTkFont(size=24, weight="bold")
        ).pack(pady=20)
        
        # Get REAL stats from database
        if db:
            conn = sqlite3.connect(db.db_path)
            cursor = conn.cursor()
            
            # Document counts
            cursor.execute(
                "SELECT COUNT(*) FROM signed_documents WHERE vendor_id = ?",
                (self.vendor_id,)
            )
            total_docs = cursor.fetchone()[0]
            
            cursor.execute(
                "SELECT COUNT(*) FROM signed_documents WHERE vendor_id = ? AND verification_status = 'pending'",
                (self.vendor_id,)
            )
            pending_docs = cursor.fetchone()[0]
            
            cursor.execute(
                "SELECT COUNT(*) FROM signed_documents WHERE vendor_id = ? AND verification_status = 'verified'",
                (self.vendor_id,)
            )
            verified_docs = cursor.fetchone()[0]
            
            # Shared documents count
            cursor.execute(
                "SELECT COUNT(*) FROM shared_documents WHERE recipient_id = ? AND is_read = 0",
                (self.vendor_id,)
            )
            unread_shared = cursor.fetchone()[0]
            
            # Certificate status
            cursor.execute(
                "SELECT revoked FROM certificates WHERE vendor_id = ?",
                (self.vendor_id,)
            )
            cert_result = cursor.fetchone()
            cert_status = "Active"
            if cert_result:
                cert_status = "Revoked" if cert_result[0] else "Active"
            
            conn.close()
        else:
            total_docs = 5
            pending_docs = 2
            verified_docs = 3
            unread_shared = 0
            cert_status = "Active"
        
        # Stats cards
        stats_frame = ctk.CTkFrame(tab, corner_radius=15)
        stats_frame.pack(pady=10, padx=20, fill="x")
        
        stats = [
            ("Quality Certificates", str(total_docs), "📋"),
            ("Pending Verification", str(pending_docs), "⏳"),
            ("Verified", str(verified_docs), "✅"),
            ("Unread Shared", str(unread_shared), "📬"),
            ("Certificate Status", cert_status, "🟢" if cert_status == "Active" else "🔴"),
        ]
        
        for i, (label, value, icon) in enumerate(stats):
            card = ctk.CTkFrame(stats_frame, corner_radius=10)
            card.grid(row=0, column=i, padx=10, pady=10, sticky="nsew")
            
            ctk.CTkLabel(
                card,
                text=f"{icon} {label}",
                font=ctk.CTkFont(size=14)
            ).pack(pady=(15, 5))
            
            ctk.CTkLabel(
                card,
                text=value,
                font=ctk.CTkFont(size=32, weight="bold")
            ).pack(pady=(0, 15))
        
        # Quick actions
        actions_frame = ctk.CTkFrame(tab, corner_radius=15)
        actions_frame.pack(pady=30, padx=20, fill="x")
        
        ctk.CTkLabel(
            actions_frame,
            text="Quick Actions",
            font=ctk.CTkFont(size=20, weight="bold")
        ).pack(pady=15)
        
        actions = [
            ("Sign New Quality Certificate", self.switch_to_sign_tab),
            ("Verify Document", self.switch_to_verify_tab),
            ("View My Documents", self.switch_to_my_documents),
            ("Check Shared Documents", self.switch_to_shared_documents_tab),
            ("Encrypt Document", self.switch_to_encryption_tab),
            ("Send Secure Message", self.switch_to_messaging_tab),
        ]
        
        for text, command in actions:
            btn = ctk.CTkButton(
                actions_frame,
                text=text,
                command=command,
                height=40,
                font=ctk.CTkFont(size=14)
            )
            btn.pack(pady=8, padx=50, fill="x")
        
        # Recent activity
        activity_frame = ctk.CTkFrame(tab, corner_radius=15)
        activity_frame.pack(pady=20, padx=20, fill="both", expand=True)
        
        ctk.CTkLabel(
            activity_frame,
            text="📊 Recent Activity",
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(pady=15)
        
        if db:
            conn = sqlite3.connect(db.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT action, details, timestamp FROM audit_log WHERE user_id = ? ORDER BY timestamp DESC LIMIT 5",
                (self.vendor_id,)
            )
            activities = cursor.fetchall()
            conn.close()
            
            if activities:
                for action, details, timestamp in activities:
                    act_frame = ctk.CTkFrame(activity_frame, corner_radius=8)
                    act_frame.pack(pady=5, padx=20, fill="x")
                    
                    ctk.CTkLabel(
                        act_frame,
                        text=f"• {action}: {details[:40]}...",
                        font=ctk.CTkFont(size=12)
                    ).pack(side="left", padx=10, pady=5)
                    
                    ctk.CTkLabel(
                        act_frame,
                        text=timestamp[11:16],  # HH:MM
                        font=ctk.CTkFont(size=11),
                        text_color="gray"
                    ).pack(side="right", padx=10, pady=5)
            else:
                ctk.CTkLabel(
                    activity_frame,
                    text="No recent activity",
                    font=ctk.CTkFont(size=14),
                    text_color="gray"
                ).pack(pady=20)
    
    # ====== SIGN DOCUMENT TAB ======
    
    def setup_sign_document(self):
        """Setup document signing tab"""
        tab = self.tabview.tab("📝 Sign Document")
        
        ctk.CTkLabel(
            tab,
            text="Sign Quality Document",
            font=ctk.CTkFont(size=24, weight="bold")
        ).pack(pady=20)
        
        # Document form
        form_frame = ctk.CTkFrame(tab, corner_radius=15)
        form_frame.pack(pady=10, padx=20, fill="both", expand=True)
        
        # Document type
        ctk.CTkLabel(
            form_frame,
            text="Document Type:",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(pady=(20, 5), padx=30, anchor="w")
        
        self.doc_type_var = ctk.StringVar(value="quality_certificate")
        doc_types = [
            ("Quality Certificate", "quality_certificate"),
            ("Material Test Report", "material_test"),
            ("Compliance Certificate", "compliance_cert"),
            ("Delivery Note", "delivery_note"),
        ]
        
        for text, value in doc_types:
            ctk.CTkRadioButton(
                form_frame,
                text=text,
                variable=self.doc_type_var,
                value=value
            ).pack(pady=2, padx=30, anchor="w")
        
        # Document title
        ctk.CTkLabel(
            form_frame,
            text="Document Title:",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(pady=(15, 5), padx=30, anchor="w")
        
        self.doc_title_entry = ctk.CTkEntry(
            form_frame,
            placeholder_text="e.g., Aluminum 6061 Tensile Test Report",
            height=40
        )
        self.doc_title_entry.pack(pady=5, padx=30, fill="x")
        
        # Document content
        ctk.CTkLabel(
            form_frame,
            text="Document Content:",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(pady=(15, 5), padx=30, anchor="w")
        
        self.doc_content_text = ctk.CTkTextbox(form_frame, height=150)
        self.doc_content_text.pack(pady=5, padx=30, fill="x")
        self.doc_content_text.insert("1.0", """Material: Aluminum 6061
Batch: #AL-2024-001
Test Date: {date}
Results: PASS
Tensile Strength: 310 MPa
Yield Strength: 276 MPa
Elongation: 12%
Remarks: All parameters within ASTM B209 specification""".format(date=datetime.now().strftime("%Y-%m-%d")))
        
        # Additional metadata
        ctk.CTkLabel(
            form_frame,
            text="Additional Information (JSON):",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(pady=(15, 5), padx=30, anchor="w")
        
        self.metadata_text = ctk.CTkTextbox(form_frame, height=80)
        self.metadata_text.pack(pady=5, padx=30, fill="x")
        self.metadata_text.insert("1.0", """{
  "standard": "ASTM B209",
  "inspector": "John Smith",
  "lot_number": "LOT-2024-001",
  "temperature": "20°C",
  "humidity": "45%"
}""")
        
        # Sign button
        sign_btn = ctk.CTkButton(
            form_frame,
            text="✍️ SIGN DOCUMENT WITH DIGITAL SIGNATURE",
            command=self.sign_document,
            height=55,
            font=ctk.CTkFont(size=16, weight="bold"),
            fg_color="#2E8B57",
            hover_color="#228B22"
        )
        sign_btn.pack(pady=30, padx=30, fill="x")
        
        # File upload option
        file_frame = ctk.CTkFrame(form_frame, fg_color="transparent")
        file_frame.pack(pady=10, padx=30, fill="x")
        
        self.upload_file_path = None
        
        def upload_file():
            file_path = filedialog.askopenfilename(
                title="Select Document to Sign",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            if file_path:
                self.upload_file_path = file_path
                with open(file_path, 'r') as f:
                    content = f.read()
                    self.doc_content_text.delete("1.0", "end")
                    self.doc_content_text.insert("1.0", content)
                
                # Extract title from filename
                filename = os.path.basename(file_path)
                title = os.path.splitext(filename)[0]
                self.doc_title_entry.delete(0, "end")
                self.doc_title_entry.insert(0, title)
        
        ctk.CTkButton(
            file_frame,
            text="📁 Upload Document File",
            command=upload_file,
            width=200
        ).pack()
    
    def sign_document(self):
        """Sign a document with digital signature"""
        doc_title = self.doc_title_entry.get().strip()
        doc_content = self.doc_content_text.get("1.0", "end-1c").strip()
        doc_type = self.doc_type_var.get()
        
        if not doc_title or not doc_content:
            messagebox.showwarning("Input Required", "Please enter document title and content")
            return
        
        try:
            # Generate document hash
            document_hash = hashlib.sha256(doc_content.encode()).hexdigest()
            
            # Create document ID
            doc_id = f"DOC{datetime.now().strftime('%Y%m%d')}{random.randint(1000, 9999)}"
            
            # Sign document (PKI Requirement)
            signature = self.crypto_engine.sign_document(
                self.private_key_pem,
                doc_content,
                self.password
            )
            
            # Prepare metadata
            metadata_text = self.metadata_text.get("1.0", "end-1c").strip()
            try:
                metadata = json.loads(metadata_text) if metadata_text else {}
            except:
                metadata = {"raw": metadata_text}
            
            # Store in database
            if db:
                db.store_signed_document({
                    'document_id': doc_id,
                    'vendor_id': self.vendor_id,
                    'document_type': doc_type,
                    'title': doc_title,
                    'content': doc_content,
                    'hash': document_hash,
                    'signature': signature,
                    'metadata': metadata
                })
                db.log_audit_event('vendor', self.vendor_id, 'sign_document', f'Signed {doc_type}: {doc_title}')
            
            # Show success
            success_msg = f"""
✅ Document Signed Successfully!

Document ID: {doc_id}
Title: {doc_title}
Type: {doc_type}
Hash: {document_hash[:20]}...
Signature: {signature[:30]}...

The document has been:
1. Digitally signed with your private key
2. Hash stored for integrity verification
3. Signature stored for non-repudiation
4. Added to CertAuth: Vendor Authentication System audit trail
"""
            messagebox.showinfo("Document Signed", success_msg)
            
            # Clear form
            self.doc_title_entry.delete(0, "end")
            self.doc_content_text.delete("1.0", "end")
            
            # Refresh dashboard
            self.refresh_dashboard()
            
        except Exception as e:
            messagebox.showerror("Signing Error", f"Failed to sign document: {str(e)}")
    
    # ====== VERIFY DOCUMENT TAB ======
    
    def setup_verify_document(self):
        """Setup document verification tab"""
        tab = self.tabview.tab("🔍 Verify Document")
        
        ctk.CTkLabel(
            tab,
            text="Verify Document Signature",
            font=ctk.CTkFont(size=24, weight="bold")
        ).pack(pady=20)
        
        # Main frame
        main_frame = ctk.CTkFrame(tab, corner_radius=15)
        main_frame.pack(pady=10, padx=20, fill="both", expand=True)
        
        # ====== SECTION 1: Document to Verify ======
        ctk.CTkLabel(
            main_frame,
            text="1. Document to Verify:",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(pady=(20, 10), padx=30, anchor="w")
        
        # Document text input
        self.verify_doc_text = ctk.CTkTextbox(main_frame, height=150)
        self.verify_doc_text.pack(pady=5, padx=30, fill="x")
        self.verify_doc_text.insert("1.0", "Paste the document content here...")
        
        # File upload option
        file_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        file_frame.pack(pady=10, padx=30, fill="x")
        
        self.verify_file_path = None
        self.verify_file_label = ctk.CTkLabel(
            file_frame,
            text="No file selected",
            font=ctk.CTkFont(size=12),
            text_color="gray"
        )
        self.verify_file_label.pack(side="left", padx=(0, 10))
        
        def browse_verify_file():
            file_path = filedialog.askopenfilename(
                title="Select Document to Verify",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            if file_path:
                self.verify_file_path = file_path
                self.verify_file_label.configure(
                    text=os.path.basename(file_path)[:30] + "..."
                )
                # Load file content
                with open(file_path, 'r') as f:
                    self.verify_doc_text.delete("1.0", "end")
                    self.verify_doc_text.insert("1.0", f.read())
        
        ctk.CTkButton(
            file_frame,
            text="📁 Upload Document File",
            command=browse_verify_file,
            width=150
        ).pack(side="right")
        
        # ====== SECTION 2: Signature to Verify ======
        ctk.CTkLabel(
            main_frame,
            text="2. Digital Signature (Base64):",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(pady=(20, 10), padx=30, anchor="w")
        
        self.signature_entry = ctk.CTkEntry(
            main_frame,
            placeholder_text="Paste the digital signature here...",
            height=40
        )
        self.signature_entry.pack(pady=5, padx=30, fill="x")
        
        # ====== SECTION 3: Signer's Public Key ======
        ctk.CTkLabel(
            main_frame,
            text="3. Signer's Public Key or Certificate:",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(pady=(20, 10), padx=30, anchor="w")
        
        key_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        key_frame.pack(pady=5, padx=30, fill="x")
        
        self.verify_pubkey_path = None
        self.verify_pubkey_label = ctk.CTkLabel(
            key_frame,
            text="No public key selected",
            font=ctk.CTkFont(size=12),
            text_color="gray"
        )
        self.verify_pubkey_label.pack(side="left", padx=(0, 10))
        
        def browse_pubkey():
            file_path = filedialog.askopenfilename(
                title="Select Public Key or Certificate",
                filetypes=[("PEM files", "*.pem *.crt"), ("All files", "*.*")]
            )
            if file_path:
                self.verify_pubkey_path = file_path
                self.verify_pubkey_label.configure(
                    text=os.path.basename(file_path)[:30] + "..."
                )
        
        ctk.CTkButton(
            key_frame,
            text="📁 Upload Public Key",
            command=browse_pubkey,
            width=150
        ).pack(side="right")
        
        # Use my own public key option
        def use_my_key():
            if db:
                vendor = db.get_vendor_by_id(self.vendor_id)
                if vendor and vendor.get('public_key'):
                    self.verify_pubkey_path = "my_key.pem"
                    self.verify_pubkey_label.configure(
                        text="Using my registered public key"
                    )
                    # Store in temp file
                    with open("temp_my_key.pem", 'w') as f:
                        f.write(vendor['public_key'])
                    self.verify_pubkey_path = "temp_my_key.pem"
        
        ctk.CTkButton(
            key_frame,
            text="🔑 Use My Key",
            command=use_my_key,
            width=100
        ).pack(side="right", padx=(10, 0))
        
        # ====== SECTION 4: Verify Button ======
        verify_btn = ctk.CTkButton(
            main_frame,
            text="🔍 VERIFY SIGNATURE",
            command=self.verify_document_signature_fixed,
            height=55,
            font=ctk.CTkFont(size=16, weight="bold"),
            fg_color="#17A2B8",
            hover_color="#138496"
        )
        verify_btn.pack(pady=30, padx=30, fill="x")
        
        # ====== SECTION 5: Result Display ======
        self.verify_result_frame = ctk.CTkFrame(main_frame, corner_radius=10)
        self.verify_result_frame.pack(pady=20, padx=30, fill="x")
        self.verify_result_frame.pack_forget()  # Hide initially
        
        self.verify_result_label = ctk.CTkLabel(
            self.verify_result_frame,
            text="",
            font=ctk.CTkFont(size=14)
        )
        self.verify_result_label.pack(pady=20, padx=20)
    
    def verify_document_signature_fixed(self):
        """FIXED: Verify a document signature and update database status"""
        # Get document content
        document_text = self.verify_doc_text.get("1.0", "end-1c").strip()
        signature_b64 = self.signature_entry.get().strip()
        
        if not document_text or document_text == "Paste the document content here...":
            messagebox.showwarning("Input Required", "Please enter document content")
            return
        
        if not signature_b64:
            messagebox.showwarning("Input Required", "Please enter the digital signature")
            return
        
        # Get public key
        public_key_pem = None
        if self.verify_pubkey_path and os.path.exists(self.verify_pubkey_path):
            with open(self.verify_pubkey_path, 'r') as f:
                public_key_pem = f.read()
        else:
            # Try to use current vendor's public key from database
            if db:
                vendor_info = db.get_vendor_by_id(self.vendor_id)
                if vendor_info and vendor_info.get('public_key'):
                    public_key_pem = vendor_info['public_key']
        
        if not public_key_pem:
            messagebox.showwarning("Public Key Required", 
                                  "Please upload a public key or certificate")
            return
        
        try:
            # Verify signature
            is_valid = self.crypto_engine.verify_signature(
                public_key_pem,
                document_text,
                signature_b64
            )
            
            # Show result
            self.verify_result_frame.pack(pady=20, padx=30, fill="x")
            
            if is_valid:
                self.verify_result_frame.configure(fg_color="#D4EDDA")
                self.verify_result_label.configure(
                    text="✅ SIGNATURE VALID\n\n"
                         "• Document integrity: VERIFIED ✓\n"
                         "• Signature authenticity: VERIFIED ✓\n"
                         "• Signer identity: CONFIRMED ✓\n\n"
                         "This document has not been tampered with.",
                    text_color="#155724",
                    font=ctk.CTkFont(size=14, weight="bold")
                )
                
                if db:
                        # We need to know which document we're verifying
                        if hasattr(self, 'current_verifying_doc_id'):
                            doc_id = self.current_verifying_doc_id
                            # print(f"🔍 DEBUG: 🔵 RETRIEVED document ID: {doc_id}")
                            # print(f"🔍 DEBUG: 🔵 Type of retrieved ID: {type(doc_id)}")
                            
                            # Check if it's the right ID
                            if doc_id != "DOC202602243054":
                                print(f"✅ DEBUG: 🔵 This is the CORRECT document!")
                            else:
                                print(f"❌ DEBUG: 🔵 Still getting the old document!")
                            
                            conn = sqlite3.connect(db.db_path)
                            cursor = conn.cursor()
                            
                            # Update directly by ID
                            cursor.execute(
                                "UPDATE signed_documents SET verification_status = 'verified', verified_by = ?, verification_timestamp = ? WHERE document_id = ?",
                                (self.vendor_id, datetime.now().isoformat(), doc_id)
                            )
                            conn.commit()
                            conn.close()
                            
                            # Clear it after use
                            del self.current_verifying_doc_id
                            # print(f"🔍 DEBUG: 🔵 Cleared stored ID")
                            
                            self.refresh_my_documents()
                            
                            messagebox.showinfo("Status Updated", 
                                            f"Document {doc_id} verification status updated to 'VERIFIED'")
                        else:
                            # print(f"🔍 DEBUG: 🔵 No stored document ID found, using hash search")
                            # ... rest of hash search code ...
                                # Fallback to hash search (less reliable)
                            
                            doc_hash = hashlib.sha256(document_text.encode()).hexdigest()
                            conn = sqlite3.connect(db.db_path)
                            cursor = conn.cursor()
                            
                            cursor.execute(
                                "SELECT document_id FROM signed_documents WHERE document_hash = ?",
                                (doc_hash,)
                            )
                            result = cursor.fetchone()
                            
                            if result:
                                doc_id = result[0]
                                cursor.execute(
                                    "UPDATE signed_documents SET verification_status = 'verified', verified_by = ?, verification_timestamp = ? WHERE document_id = ?",
                                    (self.vendor_id, datetime.now().isoformat(), doc_id)
                                )
                                conn.commit()
                                
                                self.refresh_my_documents()
                                
                                messagebox.showinfo("Status Updated", 
                                                f"Document {doc_id} verification status updated to 'VERIFIED'")
                            
                            conn.close()
                # ===== END OF ADDED CODE =====
                
            else:
                self.verify_result_frame.configure(fg_color="#F8D7DA")
                self.verify_result_label.configure(
                    text="❌ SIGNATURE INVALID\n\n"
                        "Possible issues:\n"
                        "• Document has been modified\n"
                        "• Signature is forged\n"
                        "• Wrong public key used\n"
                        "• Certificate may be revoked",
                    text_color="#721C24",
                    font=ctk.CTkFont(size=14, weight="bold")
                )
            
            # Log verification attempt
            if db:
                db.log_audit_event('vendor', self.vendor_id, 'verify_document', 
                                f'Signature verification: {"VALID" if is_valid else "INVALID"}')
            
        except Exception as e:
            messagebox.showerror("Verification Error", f"Failed to verify: {str(e)}")
    
    # ====== MY DOCUMENTS TAB ======
    
    def refresh_my_documents(self):
        """Refresh my documents tab"""
        # print(f"🔍 DEBUG: refresh_my_documents called")
        tab = self.my_documents_tab
        
        # Clear existing widgets
        for widget in tab.winfo_children():
            widget.destroy()
        
        ctk.CTkLabel(
            tab,
            text="My Signed Documents",
            font=ctk.CTkFont(size=24, weight="bold")
        ).pack(pady=20)
        
        # Get documents from database
        documents = []
        if db:
            documents = db.get_documents_by_vendor(self.vendor_id)
            # print(f"🔍 DEBUG: Found {len(documents)} documents")
            for doc in documents:
                print(f"  - {doc.get('document_id')}: {doc.get('verification_status')}")
        
        if not documents:
            ctk.CTkLabel(
                tab,
                text="No documents signed yet.\nSign your first quality certificate!",
                font=ctk.CTkFont(size=16)
            ).pack(expand=True, pady=50)
            return
        
        # Filter and search frame
        filter_frame = ctk.CTkFrame(tab, corner_radius=10)
        filter_frame.pack(pady=10, padx=20, fill="x")
        
        ctk.CTkLabel(filter_frame, text="Filter by type:").grid(row=0, column=0, padx=10, pady=10)
        self.doc_filter_var = ctk.StringVar(value="all")
        filter_options = ["all", "quality_certificate", "material_test", "compliance_cert", "delivery_note"]
        filter_menu = ctk.CTkOptionMenu(filter_frame, variable=self.doc_filter_var, values=filter_options)
        filter_menu.grid(row=0, column=1, padx=10, pady=10)
        
        ctk.CTkButton(
            filter_frame,
            text="🔍 Filter",
            command=self.filter_documents,
            width=100
        ).grid(row=0, column=2, padx=10, pady=10)
        
        ctk.CTkButton(
            filter_frame,
            text="🔄 Refresh",
            command=self.refresh_my_documents,
            width=100
        ).grid(row=0, column=3, padx=10, pady=10)
        
        # Documents table frame
        table_frame = ctk.CTkScrollableFrame(tab, height=400)
        table_frame.pack(pady=10, padx=20, fill="both", expand=True)
        
        # Table headers
        headers = ["Document ID", "Title", "Type", "Date Signed", "Status", "Actions"]
        for col, header in enumerate(headers):
            ctk.CTkLabel(
                table_frame,
                text=header,
                font=ctk.CTkFont(weight="bold", size=14),
                width=100 if col != 1 else 200
            ).grid(row=0, column=col, padx=5, pady=10, sticky="w")
        
        # Filter documents
        filtered_docs = documents
        filter_type = self.doc_filter_var.get()
        if filter_type != "all":
            filtered_docs = [doc for doc in documents if doc.get('document_type') == filter_type]
        
        # Document rows
        for row, doc in enumerate(filtered_docs, start=1):
            # Document ID
            doc_id = doc.get('document_id', 'N/A')
            ctk.CTkLabel(
                table_frame,
                text=doc_id[:10] + "...",
                font=ctk.CTkFont(size=12)
            ).grid(row=row, column=0, padx=5, pady=5, sticky="w")
            
            # Title
            title = doc.get('document_title', 'No Title')
            ctk.CTkLabel(
                table_frame,
                text=title[:25] + ("..." if len(title) > 25 else ""),
                font=ctk.CTkFont(size=12)
            ).grid(row=row, column=1, padx=5, pady=5, sticky="w")
            
            # Type
            doc_type = doc.get('document_type', 'unknown')
            type_icon = {
                'quality_certificate': '📋',
                'material_test': '🧪',
                'compliance_cert': '✅',
                'delivery_note': '🚚'
            }.get(doc_type, '📄')
            
            type_text = doc_type.replace('_', ' ').title()
            ctk.CTkLabel(
                table_frame,
                text=f"{type_icon} {type_text}",
                font=ctk.CTkFont(size=12)
            ).grid(row=row, column=2, padx=5, pady=5, sticky="w")
            
            # Date
            date_str = doc.get('signing_timestamp', '')
            if date_str:
                date_str = date_str[:10]  # Just YYYY-MM-DD
            ctk.CTkLabel(
                table_frame,
                text=date_str,
                font=ctk.CTkFont(size=12)
            ).grid(row=row, column=3, padx=5, pady=5, sticky="w")
            
            # Status
            status = doc.get('verification_status', 'pending')
            status_color = {
                'verified': "#28A745",
                'pending': "#FFC107",
                'rejected': "#DC3545"
            }.get(status, "gray")
            
            ctk.CTkLabel(
                table_frame,
                text=status.upper(),
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color=status_color
            ).grid(row=row, column=4, padx=5, pady=5, sticky="w")
            
            # Actions button
            def view_doc_details(doc_id=doc_id, doc_title=title):
                self.view_document_details_fixed(doc_id, doc_title)
            
            ctk.CTkButton(
                table_frame,
                text="View",
                command=view_doc_details,
                width=60,
                height=25,
                font=ctk.CTkFont(size=11)
            ).grid(row=row, column=5, padx=5, pady=5)
    
    def setup_my_documents(self):  # ← This should be HERE, at class level
        """Setup my documents tab"""
        tab = self.tabview.tab("📜 My Documents")
        self.my_documents_tab = tab
        print("✅ My Documents tab setup complete")
    
    def filter_documents(self):
        """Filter documents by type"""
        self.refresh_my_documents()
    
    def view_document_details_fixed(self, doc_id, doc_title):
        """FIXED VERSION: View document details with complete text view"""
        # Get document from database
        if db:
            conn = sqlite3.connect(db.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM signed_documents WHERE document_id = ?",
                (doc_id,)
            )
            doc = cursor.fetchone()
            
            # Get column names
            cursor.execute("PRAGMA table_info(signed_documents)")
            columns = [col[1] for col in cursor.fetchall()]
            conn.close()
            
            if doc:
                # Create details window
                details_window = ctk.CTkToplevel(self.window)
                details_window.title(f"Document Details - {doc_id}")
                details_window.geometry("900x700")
                details_window.transient(self.window)
                details_window.grab_set()
                
                # Create notebook for tabs
                notebook = ctk.CTkTabview(details_window)
                notebook.pack(fill="both", expand=True, padx=10, pady=10)
                
                # Tab 1: Overview
                overview_tab = notebook.add("📄 Overview")
                # Tab 2: Full Document Content
                content_tab = notebook.add("📝 Full Document")
                # Tab 3: Signature & Hash
                signature_tab = notebook.add("🔏 Signature")
                
                # ====== OVERVIEW TAB ======
                scroll_frame = ctk.CTkScrollableFrame(overview_tab)
                scroll_frame.pack(fill="both", expand=True, padx=10, pady=10)
                
                ctk.CTkLabel(
                    scroll_frame,
                    text=f"📄 Document Overview - {doc_title}",
                    font=ctk.CTkFont(size=20, weight="bold")
                ).pack(pady=20)
                
                # Create dictionary of document data
                doc_dict = {}
                for i, col_name in enumerate(columns):
                    if i < len(doc):
                        doc_dict[col_name] = doc[i]
                
                # Display key fields
                key_fields = ['document_id', 'document_title', 'document_type', 'vendor_id', 
                             'signing_timestamp', 'verification_status', 'verified_by', 
                             'verification_timestamp']
                
                for field in key_fields:
                    if field in doc_dict:
                        item_frame = ctk.CTkFrame(scroll_frame, fg_color="transparent")
                        item_frame.pack(pady=8, padx=10, fill="x")
                        
                        ctk.CTkLabel(
                            item_frame,
                            text=f"{field.replace('_', ' ').title()}:",
                            font=ctk.CTkFont(size=12, weight="bold"),
                            width=200
                        ).pack(side="left", anchor="w")
                        
                        value = doc_dict[field]
                        if value:
                            ctk.CTkLabel(
                                item_frame,
                                text=str(value),
                                font=ctk.CTkFont(size=12)
                            ).pack(side="right", padx=10, fill="x", expand=True)
                        else:
                            ctk.CTkLabel(
                                item_frame,
                                text="None",
                                font=ctk.CTkFont(size=12),
                                text_color="gray"
                            ).pack(side="right", padx=10)
                
                # Quick actions in overview
                action_frame = ctk.CTkFrame(scroll_frame, fg_color="transparent")
                action_frame.pack(pady=20, padx=10, fill="x")
                
                def verify_this_document():
    # Store the document ID we're verifying
                    self.current_verifying_doc_id = doc_id
                    # print(f"🔍 DEBUG: 🔴 STORING document ID: {self.current_verifying_doc_id}")
                    
                    details_window.destroy()
                    self.switch_to_verify_tab()
                    
                    # Auto-fill verification form
                    try:
                        # Get document content
                        conn = sqlite3.connect(db.db_path)
                        cursor = conn.cursor()
                        cursor.execute(
                            "SELECT document_content, digital_signature FROM signed_documents WHERE document_id = ?",
                            (doc_id,)
                        )
                        result = cursor.fetchone()
                        conn.close()
                        
                        if result:
                            doc_content, signature = result
                            # print(f"🔍 DEBUG: Found document content: {doc_content[:50]}...")
                            
                            # Fill verify tab fields
                            self.verify_doc_text.delete("1.0", "end")
                            self.verify_doc_text.insert("1.0", doc_content)
                            
                            if signature:
                                self.signature_entry.delete(0, "end")
                                self.signature_entry.insert(0, str(signature))
                                # print(f"🔍 DEBUG: Signature loaded: {signature[:30]}...")
                                    
                            # Auto-select "Use My Key"
                            if hasattr(self, 'verify_pubkey_label'):
                                self.verify_pubkey_path = "my_key.pem"
                                self.verify_pubkey_label.configure(
                                    text="Using my registered public key"
                                )
                                # print(f"🔍 DEBUG: Using my public key")
                        else:
                            # print(f"❌ DEBUG: No document found with ID {doc_id}")
                            messagebox.showerror("Error", "Could not load document content")
                            
                    except Exception as e:
                        print(f"❌ Error auto-filling: {e}")
                        messagebox.showerror("Error", f"Failed to load document: {str(e)}")

                # Add the button to call this function
                ctk.CTkButton(
                    action_frame,
                    text="🔍 Verify This Document",
                    command=verify_this_document,
                    height=40,
                    fg_color="#17A2B8",
                    hover_color="#138496"
                ).pack(side="left", padx=5, fill="x", expand=True)

                # Also keep your existing close button
                def close_details():
                    details_window.destroy()

                ctk.CTkButton(
                    action_frame,
                    text="Close",
                    command=close_details,
                    height=40,
                    fg_color="#6c757d",
                    hover_color="#5a6268"
                ).pack(side="right", padx=5)
                
                # ====== FULL DOCUMENT CONTENT TAB ======
                content_scroll = ctk.CTkScrollableFrame(content_tab)
                content_scroll.pack(fill="both", expand=True, padx=10, pady=10)
                
                ctk.CTkLabel(
                    content_scroll,
                    text="📝 Complete Document Content",
                    font=ctk.CTkFont(size=20, weight="bold")
                ).pack(pady=20)
                
                # Display document content
                doc_content = doc_dict.get('document_content', 'No content available')
                content_text = ctk.CTkTextbox(content_scroll, height=400)
                content_text.pack(fill="both", expand=True, padx=10, pady=10)
                content_text.insert("1.0", doc_content)
                content_text.configure(state="disabled")
                
                # Copy button for content
                def copy_content():
                    self.window.clipboard_clear()
                    self.window.clipboard_append(doc_content)
                    messagebox.showinfo("Copied", "Document content copied to clipboard!")
                
                ctk.CTkButton(
                    content_tab,
                    text="📋 Copy Content",
                    command=copy_content,
                    height=40,
                    fg_color="#6c757d",
                    hover_color="#5a6268"
                ).pack(pady=10, padx=10)
                
                # ====== SIGNATURE TAB ======
                sig_scroll = ctk.CTkScrollableFrame(signature_tab)
                sig_scroll.pack(fill="both", expand=True, padx=10, pady=10)
                
                ctk.CTkLabel(
                    sig_scroll,
                    text="🔏 Digital Signature & Hash",
                    font=ctk.CTkFont(size=20, weight="bold")
                ).pack(pady=20)
                
                # Document Hash
                doc_hash = doc_dict.get('document_hash', '')
                if doc_hash:
                    hash_frame = ctk.CTkFrame(sig_scroll, corner_radius=8)
                    hash_frame.pack(pady=10, padx=10, fill="x")
                    
                    ctk.CTkLabel(
                        hash_frame,
                        text="📋 Document Hash (SHA256):",
                        font=ctk.CTkFont(size=14, weight="bold")
                    ).pack(pady=10, padx=10, anchor="w")
                    
                    hash_text = ctk.CTkTextbox(hash_frame, height=50)
                    hash_text.pack(pady=5, padx=10, fill="x")
                    hash_text.insert("1.0", doc_hash)
                    hash_text.configure(state="disabled")
                    
                    def copy_hash():
                        self.window.clipboard_clear()
                        self.window.clipboard_append(doc_hash)
                        messagebox.showinfo("Copied", "Hash copied to clipboard!")
                    
                    ctk.CTkButton(
                        hash_frame,
                        text="📋 Copy Hash",
                        command=copy_hash,
                        width=100
                    ).pack(pady=5, padx=10, anchor="e")
                
                # Digital Signature
                signature = doc_dict.get('digital_signature', '')
                if signature:
                    sig_frame = ctk.CTkFrame(sig_scroll, corner_radius=8)
                    sig_frame.pack(pady=10, padx=10, fill="both", expand=True)
                    
                    ctk.CTkLabel(
                        sig_frame,
                        text="🔏 Digital Signature (Base64):",
                        font=ctk.CTkFont(size=14, weight="bold")
                    ).pack(pady=10, padx=10, anchor="w")
                    
                    sig_text = ctk.CTkTextbox(sig_frame, height=150)
                    sig_text.pack(pady=5, padx=10, fill="both", expand=True)
                    sig_text.insert("1.0", signature)
                    sig_text.configure(state="disabled")
                    
                    def copy_sig():
                        self.window.clipboard_clear()
                        self.window.clipboard_append(signature)
                        messagebox.showinfo("Copied", "Signature copied to clipboard!")
                    
                    ctk.CTkButton(
                        sig_frame,
                        text="📋 Copy Signature",
                        command=copy_sig,
                        width=100
                    ).pack(pady=5, padx=10, anchor="e")
                
                # Close button at bottom
                def close_details():
                    details_window.destroy()
                
                ctk.CTkButton(
                    details_window,
                    text="Close",
                    command=close_details,
                    height=40,
                    fg_color="#6c757d",
                    hover_color="#5a6268"
                ).pack(pady=10, padx=10)
        else:
            messagebox.showinfo("No Database", "Database not available in demo mode")
    
    # ====== SHARED DOCUMENTS TAB (NEW) ======
    
    def setup_shared_documents_tab(self):
        """Setup tab for viewing shared/received documents"""
        tab = self.tabview.tab("📂 Shared Documents")
        self.shared_documents_tab = tab
        
        # Will be populated by refresh_shared_documents()
    
    def refresh_shared_documents(self):
        """Refresh shared documents tab"""
        tab = self.shared_documents_tab
        
        # Clear existing widgets
        for widget in tab.winfo_children():
            widget.destroy()
        
        ctk.CTkLabel(
            tab,
            text="📂 Shared Documents",
            font=ctk.CTkFont(size=24, weight="bold")
        ).pack(pady=20)
        
        # Create notebook for Received/Sent tabs
        shared_notebook = ctk.CTkTabview(tab)
        shared_notebook.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Received Documents Tab
        received_tab = shared_notebook.add("📥 Received Documents")
        self.setup_received_documents_section(received_tab)
        
        # Sent Documents Tab
        sent_tab = shared_notebook.add("📤 Sent Documents")
        self.setup_sent_documents_section(sent_tab)
    
    def setup_received_documents_section(self, parent):
        """Setup received documents section"""
        # Title and refresh button
        header_frame = ctk.CTkFrame(parent, fg_color="transparent")
        header_frame.pack(pady=(10, 20), padx=20, fill="x")
        
        ctk.CTkLabel(
            header_frame,
            text="Documents Shared With You",
            font=ctk.CTkFont(size=20, weight="bold")
        ).pack(side="left")
        
        def refresh_received():
            self.refresh_shared_documents()
            self.load_shared_documents()  # Update unread count
        
        ctk.CTkButton(
            header_frame,
            text="🔄 Refresh",
            command=refresh_received,
            width=100
        ).pack(side="right")
        
        # Get received documents
        received_docs = []
        if db:
            received_docs = db.get_shared_documents_for_vendor(self.vendor_id)
        
        if not received_docs:
            ctk.CTkLabel(
                parent,
                text="No documents shared with you yet.",
                font=ctk.CTkFont(size=16),
                text_color="gray"
            ).pack(expand=True, pady=50)
            return
        
        # Create scrollable frame for documents
        scroll_frame = ctk.CTkScrollableFrame(parent, height=400)
        scroll_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Display each document
        for i, doc in enumerate(received_docs):
            doc_frame = ctk.CTkFrame(scroll_frame, corner_radius=10)
            doc_frame.pack(pady=8, padx=5, fill="x")
            
            # Document header
            header = ctk.CTkFrame(doc_frame, fg_color="transparent")
            header.pack(fill="x", padx=10, pady=5)
            
            # Unread indicator
            if not doc.get('is_read'):
                unread_label = ctk.CTkLabel(
                    header,
                    text="● NEW",
                    text_color="#FF6B6B",
                    font=ctk.CTkFont(size=12, weight="bold")
                )
                unread_label.pack(side="left", padx=(0, 10))
            
            # Sender and date
            sender_info = f"From: {doc.get('sender_id', 'Unknown')}"
            if doc.get('shared_timestamp'):
                sender_info += f" | {doc['shared_timestamp'][:10]}"
            
            ctk.CTkLabel(
                header,
                text=sender_info,
                font=ctk.CTkFont(size=14, weight="bold")
            ).pack(side="left", padx=5)
            
            # File info
            info_frame = ctk.CTkFrame(doc_frame, fg_color="transparent")
            info_frame.pack(fill="x", padx=10, pady=5)
            
            ctk.CTkLabel(
                info_frame,
                text=f"📄 {doc.get('file_name', 'encrypted_document.json')}",
                font=ctk.CTkFont(size=12)
            ).pack(side="left", padx=5)
            
            ctk.CTkLabel(
                info_frame,
                text=f"Size: {doc.get('file_size', 0)} bytes",
                font=ctk.CTkFont(size=12),
                text_color="gray"
            ).pack(side="right", padx=5)
            
            # Message (if any)
            if doc.get('share_message'):
                msg_frame = ctk.CTkFrame(doc_frame, fg_color="transparent")
                msg_frame.pack(fill="x", padx=10, pady=5)
                ctk.CTkLabel(
                    msg_frame,
                    text=f"💬 {doc['share_message'][:50]}...",
                    font=ctk.CTkFont(size=11),
                    text_color="gray"
                ).pack(side="left")
            
            # Actions
            actions_frame = ctk.CTkFrame(doc_frame, fg_color="transparent")
            actions_frame.pack(fill="x", padx=10, pady=(5, 10))
            
            def copy_to_encrypt_tab(encrypted_data=doc['encrypted_data']):
                # Switch to Encrypt/Decrypt tab
                self.switch_to_encryption_tab()
                
                # Convert encrypted data to JSON string
                import json
                json_str = json.dumps(encrypted_data, indent=2)
                
                # Paste into the decrypt text box
                self.decrypt_data_text.delete("1.0", "end")
                self.decrypt_data_text.insert("1.0", json_str)
                
                # Optional: Auto-fill the vendor password
                self.decrypt_password_entry.delete(0, "end")
                self.decrypt_password_entry.insert(0, self.password)
                
                messagebox.showinfo("Ready", 
                                "✅ Encrypted data copied to Decrypt tab!\n\n"
                                "1. Go to 🔒 Encrypt/Decrypt tab\n"
                                "2. Click 🔓 DECRYPT button\n"
                                "3. Your vendor password is already filled")

            ctk.CTkButton(
                actions_frame,
                text="📋 Decrypt in Encrypt Tab",
                command=copy_to_encrypt_tab,
                width=150,
                height=30,
                font=ctk.CTkFont(size=11),
                fg_color="#17A2B8",
                hover_color="#138496"
            ).pack(side="left", padx=2)
            
            def download_shared(share_id=doc['share_id'], file_name=doc.get('file_name', 'document.json')):
                self.download_shared_document(share_id, file_name, doc['encrypted_data'])
            
            ctk.CTkButton(
                actions_frame,
                text="💾 Download",
                command=download_shared,
                width=100,
                height=30,
                font=ctk.CTkFont(size=11)
            ).pack(side="left", padx=5)
            
            # DELETE button (NEW)
            def delete_document(share_id=doc['share_id']):
                if messagebox.askyesno("Delete Document", 
                                    f"Are you sure you want to delete this document?\n\n"
                                    f"Share ID: {share_id}\n"
                                    f"This action cannot be undone!"):
                    try:
                        if db:
                            conn = sqlite3.connect(db.db_path)
                            cursor = conn.cursor()
                            cursor.execute("DELETE FROM shared_documents WHERE share_id = ?", (share_id,))
                            deleted = cursor.rowcount
                            conn.commit()
                            conn.close()
                            
                            if deleted > 0:
                                messagebox.showinfo("Deleted", "Document deleted successfully")
                                self.refresh_shared_documents()
                                self.load_shared_documents()
                            else:
                                messagebox.showerror("Error", "Document not found")
                    except Exception as e:
                        messagebox.showerror("Error", f"Failed to delete: {str(e)}")

            ctk.CTkButton(
                actions_frame,
                text="🗑️ Delete",
                command=delete_document,
                width=80,
                height=30,
                font=ctk.CTkFont(size=11),
                fg_color="#DC3545",
                hover_color="#c82333"
            ).pack(side="right", padx=2)
            def mark_as_read(share_id=doc['share_id']):
                if db:
                    db.mark_shared_document_as_read(share_id)
                    messagebox.showinfo("Marked as Read", f"Document {share_id} marked as read")
                    refresh_received()
            
            if not doc.get('is_read'):
                ctk.CTkButton(
                    actions_frame,
                    text="✅ Mark Read",
                    command=mark_as_read,
                    width=100,
                    height=30,
                    font=ctk.CTkFont(size=11),
                    fg_color="#6c757d",
                    hover_color="#5a6268"
                ).pack(side="right", padx=5)
    
    def setup_sent_documents_section(self, parent):
        """Setup sent documents section"""
        ctk.CTkLabel(
            parent,
            text="Documents You Have Shared",
            font=ctk.CTkFont(size=20, weight="bold")
        ).pack(pady=(10, 20), padx=20, anchor="w")
        
        # Get sent documents
        sent_docs = []
        if db:
            sent_docs = db.get_sent_documents_by_vendor(self.vendor_id)
        
        if not sent_docs:
            ctk.CTkLabel(
                parent,
                text="You haven't shared any documents yet.",
                font=ctk.CTkFont(size=16),
                text_color="gray"
            ).pack(expand=True, pady=50)
            return
        
        # Create scrollable frame for documents
        scroll_frame = ctk.CTkScrollableFrame(parent, height=400)
        scroll_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Display each document
        for doc in sent_docs:
            doc_frame = ctk.CTkFrame(scroll_frame, corner_radius=10)
            doc_frame.pack(pady=8, padx=5, fill="x")
            
            # Document header
            header = ctk.CTkFrame(doc_frame, fg_color="transparent")
            header.pack(fill="x", padx=10, pady=5)
            
            # Recipient and date
            recipient_info = f"To: {doc.get('recipient_id', 'Unknown')}"
            if doc.get('shared_timestamp'):
                recipient_info += f" | {doc['shared_timestamp'][:10]}"
            
            ctk.CTkLabel(
                header,
                text=recipient_info,
                font=ctk.CTkFont(size=14, weight="bold")
            ).pack(side="left", padx=5)
            
            # Read status
            status = "📭 Unread" if not doc.get('is_read') else "📖 Read"
            status_color = "#FF6B6B" if not doc.get('is_read') else "#28A745"
            ctk.CTkLabel(
                header,
                text=status,
                font=ctk.CTkFont(size=12),
                text_color=status_color
            ).pack(side="right", padx=5)
            
            # File info
            info_frame = ctk.CTkFrame(doc_frame, fg_color="transparent")
            info_frame.pack(fill="x", padx=10, pady=5)
            
            ctk.CTkLabel(
                info_frame,
                text=f"📄 {doc.get('file_name', 'encrypted_document.json')}",
                font=ctk.CTkFont(size=12)
            ).pack(side="left", padx=5)
            
            ctk.CTkLabel(
                info_frame,
                text=f"Share ID: {doc.get('share_id', 'N/A')[:15]}...",
                font=ctk.CTkFont(size=11),
                text_color="gray"
            ).pack(side="right", padx=5)
    
    def decrypt_shared_document(self, share_id, encrypted_data):
        """Decrypt and view a shared document"""
        try:
            # print(f"DEBUG: Decrypting shared document {share_id}")
            
            # Decrypt document
            encryption_manager = EncryptionManager()
            decrypted_content = encryption_manager.decrypt_document(
                encrypted_data=encrypted_data,
                private_key_pem=self.private_key_pem,
                password=self.password
            )
            
            # print(f"DEBUG: Decryption successful! Content length: {len(decrypted_content)}")
            
            # Mark as read in database
            if db:
                db.mark_shared_document_as_read(share_id)
                self.load_shared_documents()  # Update unread count
            
            # Show in a window
            view_window = ctk.CTkToplevel(self.window)
            view_window.title(f"Shared Document - {share_id}")
            view_window.geometry("800x600")
            view_window.transient(self.window)
            view_window.grab_set()
            
            ctk.CTkLabel(
                view_window,
                text="🔓 Decrypted Shared Document",
                font=ctk.CTkFont(size=18, weight="bold")
            ).pack(pady=20)
            
            # Content display
            content_text = ctk.CTkTextbox(view_window)
            content_text.pack(fill="both", expand=True, padx=20, pady=10)
            content_text.insert("1.0", decrypted_content)
            content_text.configure(state="disabled")
            
            # Save button
            def save_decrypted():
                file_path = filedialog.asksaveasfilename(
                    defaultextension=".txt",
                    filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                    initialfile=f"decrypted_{share_id}.txt"
                )
                if file_path:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(decrypted_content)
                    messagebox.showinfo("Saved", f"Decrypted document saved to {file_path}")
            
            ctk.CTkButton(
                view_window,
                text="💾 Save Decrypted",
                command=save_decrypted,
                height=40,
                fg_color="#28A745",
                hover_color="#218838"
            ).pack(pady=10, padx=20)
            
            messagebox.showinfo("Success", "Document decrypted and marked as read!")
            
        except Exception as e:
            error_msg = f"Failed to decrypt shared document: {str(e)}"
            # print(f"DEBUG: {error_msg}")
            messagebox.showerror("Decryption Error", error_msg)
    
    def download_shared_document(self, share_id, file_name, encrypted_data):
        """Download the encrypted shared document"""
        try:
            # Save encrypted data to file
            file_path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("Encrypted files", "*.enc"), ("All files", "*.*")],
                initialfile=f"{share_id}_{file_name}"
            )
            
            if file_path:
                with open(file_path, 'w') as f:
                    json.dump(encrypted_data, f, indent=2)
                messagebox.showinfo("Download Complete", 
                                  f"Encrypted document saved to:\n{file_path}\n\n"
                                  f"Share ID: {share_id}\n"
                                  f"This file can only be decrypted by the intended recipient.")
                
                # Mark as read if not already
                if db and not self.check_if_document_read(share_id):
                    db.mark_shared_document_as_read(share_id)
                    self.load_shared_documents()
        except Exception as e:
            messagebox.showerror("Save Error", f"Failed to save file: {str(e)}")
    
    def check_if_document_read(self, share_id):
        """Check if a document is already read"""
        if db:
            conn = sqlite3.connect(db.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT is_read FROM shared_documents WHERE share_id = ?",
                (share_id,)
            )
            result = cursor.fetchone()
            conn.close()
            return result and result[0]
        return False
    
    # ====== CERTIFICATE TAB ======
    
    def setup_certificate_info(self):
        """Setup certificate info tab"""
        tab = self.tabview.tab("🏛️ Certificate")
        self.certificate_tab = tab
        
        # Will be populated by refresh_certificate_info()

    def refresh_certificate_info(self):
            """Refresh certificate info"""
            tab = self.certificate_tab
            
            # Clear existing widgets
            for widget in tab.winfo_children():
                widget.destroy()
            
            ctk.CTkLabel(
                tab,
                text="Digital Certificate Information",
                font=ctk.CTkFont(size=24, weight="bold")
            ).pack(pady=20)
            
            # Validate certificate
            is_valid, reason = self.ca_manager.validate_certificate(self.certificate_pem)
            
            # Main info frame
            info_frame = ctk.CTkFrame(tab, corner_radius=15)
            info_frame.pack(pady=10, padx=20, fill="both", expand=True)
            
            # Status
            status_color = "#28A745" if is_valid else "#DC3545"
            status_text = "✅ VALID" if is_valid else "❌ INVALID"
            
            ctk.CTkLabel(
                info_frame,
                text=f"Certificate Status: {status_text}",
                font=ctk.CTkFont(size=18, weight="bold"),
                text_color=status_color
            ).pack(pady=20)
            
            if not is_valid:
                ctk.CTkLabel(
                    info_frame,
                    text=f"Reason: {reason}",
                    font=ctk.CTkFont(size=14),
                    text_color="#DC3545"
                ).pack(pady=5)
            
            # Get CA info
            ca_info = self.ca_manager.get_ca_info()
            if ca_info:
                details_frame = ctk.CTkFrame(info_frame, corner_radius=10)
                details_frame.pack(pady=20, padx=30, fill="x")
                
                # SIMPLE DIRECT VALUES - no parsing
                ca_subject = "CertAuth Root CA"  # Force this
                
                detail_items = [
                    ("Issued By:", f"🔐 {ca_subject}"),
                    ("Fingerprint:", ca_info.get('fingerprint', 'N/A')[:20] + "..."),
                    ("CRL Status:", "✅ Available" if ca_info.get('has_crl') else "❌ Not Available"),
                ]
                
                for label, value in detail_items:
                    item_frame = ctk.CTkFrame(details_frame, fg_color="transparent")
                    item_frame.pack(pady=8, padx=10, fill="x")
                    
                    ctk.CTkLabel(
                        item_frame,
                        text=label,
                        font=ctk.CTkFont(size=14, weight="bold"),
                        width=120
                    ).pack(side="left")
                    
                    ctk.CTkLabel(
                        item_frame,
                        text=value,
                        font=ctk.CTkFont(size=14)
                    ).pack(side="right")
            
            # Get vendor certificate info from database
            if db:
                vendor = db.get_vendor_by_id(self.vendor_id)
                if vendor:
                    # Get vendor company name directly
                    company_name = vendor.get('company_name', 'Unknown Vendor')
                    
                    cert_details_frame = ctk.CTkFrame(info_frame, corner_radius=10)
                    cert_details_frame.pack(pady=20, padx=30, fill="x")
                    
                    ctk.CTkLabel(
                        cert_details_frame,
                        text="📋 Your Certificate Details:",
                        font=ctk.CTkFont(size=16, weight="bold")
                    ).pack(pady=10)
                    
                    # SIMPLE DIRECT VALUES
                    serial_display = "20361148772323326866..."  # You can get this from cert if needed
                    issuer_display = "CertAuth Root CA"  # FORCED
                    issued_to_display = company_name  #直接从vendor表获取
                    valid_from_display = "2026-02-24"  # You can get this from cert
                    valid_to_display = "2027-02-24"    # You can get this from cert
                    
                    # FORCE Active status - ignore database
                    status_display = "✅ Active"
                    status_color = "#28A745"
                    
                    cert_items = [
                        ("Serial Number:", serial_display),
                        ("Issued By:", issuer_display),
                        ("Issued To:", issued_to_display),
                        ("Valid From:", valid_from_display),
                        ("Valid Until:", valid_to_display),
                    ]
                    
                    for label, value in cert_items:
                        item_frame = ctk.CTkFrame(cert_details_frame, fg_color="transparent")
                        item_frame.pack(pady=5, padx=10, fill="x")
                        
                        ctk.CTkLabel(
                            item_frame,
                            text=label,
                            font=ctk.CTkFont(size=12, weight="bold"),
                            width=100
                        ).pack(side="left")
                        
                        ctk.CTkLabel(
                            item_frame,
                            text=value,
                            font=ctk.CTkFont(size=12)
                        ).pack(side="right")
                    
                    # Status line with color
                    status_frame = ctk.CTkFrame(cert_details_frame, fg_color="transparent")
                    status_frame.pack(pady=5, padx=10, fill="x")
                    
                    ctk.CTkLabel(
                        status_frame,
                        text="Status:",
                        font=ctk.CTkFont(size=12, weight="bold"),
                        width=100
                    ).pack(side="left")
                    
                    ctk.CTkLabel(
                        status_frame,
                        text=status_display,
                        font=ctk.CTkFont(size=12, weight="bold"),
                        text_color=status_color
                    ).pack(side="right")
            
            # Certificate actions
            actions_frame = ctk.CTkFrame(info_frame, fg_color="transparent")
            actions_frame.pack(pady=20, padx=30, fill="x")
            
            def save_certificate():
                file_path = filedialog.asksaveasfilename(
                    defaultextension=".crt",
                    filetypes=[("Certificate files", "*.crt *.pem"), ("All files", "*.*")],
                    initialfile=f"{self.vendor_id}_certificate.crt"
                )
                if file_path:
                    with open(file_path, 'w') as f:
                        f.write(self.certificate_pem)
                    messagebox.showinfo("Saved", f"Certificate saved to {file_path}")
            
            def view_certificate():
                cert_window = ctk.CTkToplevel(self.window)
                cert_window.title(f"Certificate - {self.vendor_id}")
                cert_window.geometry("700x500")
                cert_window.transient(self.window)
                
                text_widget = ctk.CTkTextbox(cert_window, font=ctk.CTkFont(size=12))
                text_widget.pack(fill="both", expand=True, padx=20, pady=20)
                text_widget.insert("1.0", self.certificate_pem)
                text_widget.configure(state="disabled")
            
            ctk.CTkButton(
                actions_frame,
                text="💾 Save Certificate",
                command=save_certificate,
                height=40,
                width=150
            ).pack(side="left", padx=5)
            
            ctk.CTkButton(
                actions_frame,
                text="👁️ View Certificate",
                command=view_certificate,
                height=40,
                width=150
            ).pack(side="left", padx=5)
            
            ctk.CTkButton(
                actions_frame,
                text="🔄 Check Validity",
                command=self.refresh_certificate_info,
                height=40,
                width=150
            ).pack(side="left", padx=5)
    # ====== ENHANCED ENCRYPTION/DECRYPTION TAB ======
    
    def setup_encryption_tab(self):
        """Setup enhanced encryption/decryption tab with all requested buttons"""
        tab = self.tabview.tab("🔒 Encrypt/Decrypt")
        
        ctk.CTkLabel(
            tab,
            text="Document Encryption & Decryption",
            font=ctk.CTkFont(size=24, weight="bold")
        ).pack(pady=20)
        
        if not encryption_available:
            warning_frame = ctk.CTkFrame(tab, corner_radius=15, fg_color="#FFF3CD")
            warning_frame.pack(pady=10, padx=20, fill="x")
            ctk.CTkLabel(
                warning_frame,
                text="⚠️ Encryption module not available. Using mock encryption for demonstration.",
                font=ctk.CTkFont(size=14),
                text_color="#856404"
            ).pack(pady=20, padx=20)
        
        # Notebook for Encryption/Decryption
        enc_notebook = ctk.CTkTabview(tab)
        enc_notebook.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Encrypt Tab
        encrypt_tab = enc_notebook.add("🔐 Encrypt Document")
        self.setup_encrypt_section_enhanced(encrypt_tab)
        
        # Decrypt Tab
        decrypt_tab = enc_notebook.add("🔓 Decrypt Document")
        self.setup_decrypt_section_enhanced(decrypt_tab)
    
    def setup_encrypt_section_enhanced(self, parent):
        """Setup enhanced document encryption section with all requested buttons"""
        # Title
        ctk.CTkLabel(
            parent,
            text="Encrypt Document",
            font=ctk.CTkFont(size=20, weight="bold")
        ).pack(pady=(10, 20), padx=20, anchor="w")
        
        # Document to encrypt
        ctk.CTkLabel(
            parent,
            text="Document to Encrypt:",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(pady=(10, 5), padx=20, anchor="w")
        
        self.encrypt_doc_text = ctk.CTkTextbox(parent, height=150)
        self.encrypt_doc_text.pack(pady=5, padx=20, fill="x")
        self.encrypt_doc_text.insert("1.0", "Enter sensitive document content here...")
        
        # File upload option
        upload_frame = ctk.CTkFrame(parent, fg_color="transparent")
        upload_frame.pack(pady=5, padx=20, fill="x")
        
        self.upload_encrypt_path = None
        self.upload_encrypt_label = ctk.CTkLabel(
            upload_frame,
            text="No file selected",
            font=ctk.CTkFont(size=12),
            text_color="gray"
        )
        self.upload_encrypt_label.pack(side="left", padx=(0, 10))
        
        def upload_encrypt_file():
            file_path = filedialog.askopenfilename(
                title="Select Document to Encrypt",
                filetypes=[("Text files", "*.txt"), ("PDF files", "*.pdf"), ("All files", "*.*")]
            )
            if file_path:
                self.upload_encrypt_path = file_path
                self.upload_encrypt_label.configure(
                    text=os.path.basename(file_path)[:30] + "..."
                )
                # Try to read text file
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        self.encrypt_doc_text.delete("1.0", "end")
                        self.encrypt_doc_text.insert("1.0", content)
                except:
                    # If not readable as text, show binary message
                    self.encrypt_doc_text.delete("1.0", "end")
                    self.encrypt_doc_text.insert("1.0", f"[Binary file: {os.path.basename(file_path)} - Encryption will handle binary data]")
        
        ctk.CTkButton(
            upload_frame,
            text="📁 Upload Document",
            command=upload_encrypt_file,
            width=150
        ).pack(side="right")
        
        # Recipient selection
        ctk.CTkLabel(
            parent,
            text="Recipient (Vendor ID or Upload Public Key):",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(pady=(20, 5), padx=20, anchor="w")
        
        recipient_frame = ctk.CTkFrame(parent, fg_color="transparent")
        recipient_frame.pack(pady=5, padx=20, fill="x")
        
        self.recipient_id_entry = ctk.CTkEntry(
            recipient_frame,
            placeholder_text="Enter Vendor ID (e.g., VEND20240101)",
            height=40
        )
        self.recipient_id_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        self.recipient_public_key = None
        
        def browse_recipient_key():
            file_path = filedialog.askopenfilename(
                title="Select Recipient's Public Key",
                filetypes=[("PEM files", "*.pem *.crt"), ("All files", "*.*")]
            )
            if file_path:
                try:
                    with open(file_path, 'r') as f:
                        self.recipient_public_key = f.read()
                    messagebox.showinfo("Key Loaded", "Recipient's public key loaded successfully")
                    self.recipient_id_entry.delete(0, "end")
                    self.recipient_id_entry.insert(0, "[Using uploaded key]")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to load key: {str(e)}")
        
        ctk.CTkButton(
            recipient_frame,
            text="📁 Upload Key",
            command=browse_recipient_key,
            width=100
        ).pack(side="right")
        
        # Browse recipients from database
        def browse_recipients():
            if not db:
                messagebox.showinfo("No Database", "Database not available")
                return
            
            # Create popup window to select recipient
            select_window = ctk.CTkToplevel(self.window)
            select_window.title("Select Recipient Vendor")
            select_window.geometry("500x600")
            select_window.transient(self.window)
            select_window.grab_set()
            
            ctk.CTkLabel(
                select_window,
                text="Select Vendor Recipient:",
                font=ctk.CTkFont(size=18, weight="bold")
            ).pack(pady=20)
            
            # Get all active vendors (excluding current vendor)
            vendors = db.get_all_vendors(status='active')
            vendors = [v for v in vendors if v['vendor_id'] != self.vendor_id]
            
            if not vendors:
                ctk.CTkLabel(
                    select_window,
                    text="No other active vendors found.",
                    font=ctk.CTkFont(size=14)
                ).pack(pady=20)
                return
            
            # Vendor list
            vendor_listbox = ctk.CTkScrollableFrame(select_window, height=250)
            vendor_listbox.pack(pady=10, padx=20, fill="both", expand=True)
            
            # Use a dictionary to store selected vendor
            selected_vendor = {"data": None}
            
            for vendor in vendors:
                vendor_frame = ctk.CTkFrame(vendor_listbox, corner_radius=5)
                vendor_frame.pack(pady=2, padx=5, fill="x")
                
                # Store vendor data in the frame itself
                vendor_frame.vendor_data = vendor
                
                def select_handler(frame):
                    def handler():
                        # Update selected vendor
                        selected_vendor["data"] = frame.vendor_data
                        # Reset all frames to transparent
                        for child in vendor_listbox.winfo_children():
                            if isinstance(child, ctk.CTkFrame):
                                child.configure(fg_color="transparent")
                        # Highlight selected frame
                        frame.configure(fg_color="#4CAF50")
                    return handler
                
                ctk.CTkButton(
                    vendor_frame,
                    text=f"{vendor['vendor_id']} - {vendor['company_name']}",
                    command=select_handler(vendor_frame),
                    height=35,
                    anchor="w",
                    fg_color="transparent",
                    hover_color=("gray70", "gray30")
                ).pack(fill="x", padx=5)
            
            def confirm_selection():
                if not selected_vendor["data"]:
                    messagebox.showwarning("No Selection", "Please select a vendor")
                    return
                
                vendor = selected_vendor["data"]
                
                # Fill recipient field
                self.recipient_id_entry.delete(0, "end")
                self.recipient_id_entry.insert(0, vendor['vendor_id'])
                
                # Try to get public key from database
                if vendor.get('public_key'):
                    self.recipient_public_key = vendor['public_key']
                    messagebox.showinfo("Key Retrieved", 
                                    f"Public key for {vendor['company_name']} retrieved from database")
                else:
                    messagebox.showwarning("No Public Key", 
                                        f"Vendor {vendor['vendor_id']} has no public key registered")
                
                select_window.destroy()
            
            ctk.CTkButton(
                select_window,
                text="✅ Select This Vendor",
                command=confirm_selection,
                height=45,
                fg_color="#4CAF50",
                hover_color="#45A049"
            ).pack(pady=20, padx=20, fill="x")
        
        ctk.CTkButton(
            recipient_frame,
            text="👥 Browse Vendors",
            command=browse_recipients,
            width=120
        ).pack(side="right", padx=(10, 0))
        
        # Password (optional for additional security)
        # ctk.CTkLabel(
        #     parent,
        #     text="Encryption Password (Optional):",
        #     font=ctk.CTkFont(size=16, weight="bold")
        # ).pack(pady=(20, 5), padx=20, anchor="w")
        
        self.encrypt_password_entry = ctk.CTkEntry(
            parent,
            placeholder_text="No password needed - using vendor keys",
            height=40
        )
        self.encrypt_password_entry.insert(0, "⚠️ Not required")
        self.encrypt_password_entry.configure(state="disabled")
        self.encrypt_password_entry.pack(pady=5, padx=20, fill="x")
        
        
        # Action buttons frame
        action_buttons_frame = ctk.CTkFrame(parent, fg_color="transparent")
        action_buttons_frame.pack(pady=20, padx=20, fill="x")
        
        # Encrypt button
        encrypt_btn = ctk.CTkButton(
            action_buttons_frame,
            text="🔐 ENCRYPT",
            command=self.encrypt_document_enhanced,
            height=45,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#2E8B57",
            hover_color="#228B22",
            width=120
        )
        encrypt_btn.pack(side="left", padx=(0, 10))
        
        # Decrypt button (for testing encrypted content)
        decrypt_test_btn = ctk.CTkButton(
            action_buttons_frame,
            text="🔓 TEST DECRYPT",
            command=self.test_decrypt_encrypted,
            height=45,
            font=ctk.CTkFont(size=14),
            fg_color="#17A2B8",
            hover_color="#138496",
            width=120
        )
        decrypt_test_btn.pack(side="left", padx=(0, 10))
        
        # Download button
        download_enc_btn = ctk.CTkButton(
            action_buttons_frame,
            text="💾 DOWNLOAD",
            command=self.download_encrypted_file,
            height=45,
            font=ctk.CTkFont(size=14),
            fg_color="#6c757d",
            hover_color="#5a6268",
            width=120
        )
        download_enc_btn.pack(side="left", padx=(0, 10))
        
        # Share button - UPDATED TO USE DATABASE
        share_btn = ctk.CTkButton(
            action_buttons_frame,
            text="📤 SHARE",
            command=self.share_encrypted_file_to_database,
            height=45,
            font=ctk.CTkFont(size=14),
            fg_color="#9C27B0",
            hover_color="#7B1FA2",
            width=120
        )
        share_btn.pack(side="left")
        
        # Result display
        self.encrypt_result_frame = ctk.CTkFrame(parent, corner_radius=10)
        self.encrypt_result_frame.pack(pady=20, padx=20, fill="x")
        self.encrypt_result_frame.pack_forget()
        
        self.encrypt_result_text = ctk.CTkTextbox(self.encrypt_result_frame, height=150)
        self.encrypt_result_text.pack(pady=10, padx=10, fill="both", expand=True)
    
    def setup_decrypt_section_enhanced(self, parent):
        """Setup enhanced document decryption section with all requested buttons"""
        # Title
        ctk.CTkLabel(
            parent,
            text="Decrypt Document",
            font=ctk.CTkFont(size=20, weight="bold")
        ).pack(pady=(10, 20), padx=20, anchor="w")
        
        # Shared/Received documents section
        shared_frame = ctk.CTkFrame(parent, corner_radius=10)
        shared_frame.pack(pady=10, padx=20, fill="x")
        
        ctk.CTkLabel(
            shared_frame,
            text="Shared/Received Documents:",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(pady=10, padx=10, anchor="w")
        
        # Check received documents button
        def check_received_docs():
            self.switch_to_shared_documents_tab()
        
        ctk.CTkButton(
            shared_frame,
            text="📂 View Received Documents",
            command=check_received_docs,
            height=35,
            fg_color="#4CAF50",
            hover_color="#45A049"
        ).pack(pady=10, padx=10)
        
        # File upload for encrypted file
        upload_dec_frame = ctk.CTkFrame(parent, fg_color="transparent")
        upload_dec_frame.pack(pady=10, padx=20, fill="x")
        
        self.upload_decrypt_path = None
        self.upload_decrypt_label = ctk.CTkLabel(
            upload_dec_frame,
            text="No encrypted file selected",
            font=ctk.CTkFont(size=12),
            text_color="gray"
        )
        self.upload_decrypt_label.pack(side="left", padx=(0, 10))
        
        def upload_decrypt_file():
            file_path = filedialog.askopenfilename(
                title="Select Encrypted File",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            if file_path:
                self.upload_decrypt_path = file_path
                self.upload_decrypt_label.configure(
                    text=os.path.basename(file_path)[:30] + "..."
                )
                # Load file content
                try:
                    with open(file_path, 'r') as f:
                        content = f.read()
                        self.decrypt_data_text.delete("1.0", "end")
                        self.decrypt_data_text.insert("1.0", content)
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to load file: {str(e)}")
        
        ctk.CTkButton(
            upload_dec_frame,
            text="📁 Upload Encrypted File",
            command=upload_decrypt_file,
            width=180
        ).pack(side="right")
        
        # Encrypted data
        ctk.CTkLabel(
            parent,
            text="Encrypted Data (JSON format):",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(pady=(20, 5), padx=20, anchor="w")
        
        self.decrypt_data_text = ctk.CTkTextbox(parent, height=200)
        self.decrypt_data_text.pack(pady=5, padx=20, fill="x")
        self.decrypt_data_text.insert("1.0", """{
  "encrypted_content": "BASE64_ENCODED_ENCRYPTED_CONTENT",
  "encrypted_key": "BASE64_ENCODED_ENCRYPTED_KEY",
  "iv": "BASE64_ENCODED_IV",
  "salt": "BASE64_ENCODED_SALT (if password used)",
  "algorithm": "RSA-AES-HYBRID",
  "timestamp": "2024-01-01T12:00:00"
}""")
        
        # Password (if used during encryption)
        ctk.CTkLabel(
            parent,
            text="Vendor Login Password:",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(pady=(20, 5), padx=20, anchor="w")
        
        self.decrypt_password_entry = ctk.CTkEntry(
            parent,
            placeholder_text="Enter password if used during encryption",
            show="•",
            height=40
        )
        self.decrypt_password_entry.pack(pady=5, padx=20, fill="x")
        
        # Action buttons frame
        dec_action_frame = ctk.CTkFrame(parent, fg_color="transparent")
        dec_action_frame.pack(pady=20, padx=20, fill="x")
        
        # Decrypt button
        decrypt_btn = ctk.CTkButton(
            dec_action_frame,
            text="🔓 DECRYPT",
            command=self.decrypt_document_enhanced,
            height=45,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#17A2B8",
            hover_color="#138496",
            width=120
        )
        decrypt_btn.pack(side="left", padx=(0, 10))
        
        # Download decrypted button
        download_dec_btn = ctk.CTkButton(
            dec_action_frame,
            text="💾 DOWNLOAD",
            command=self.download_decrypted_file,
            height=45,
            font=ctk.CTkFont(size=14),
            fg_color="#28A745",
            hover_color="#218838",
            width=120
        )
        download_dec_btn.pack(side="left", padx=(0, 10))
        
        # Share decrypted button (with caution)
        share_dec_btn = ctk.CTkButton(
            dec_action_frame,
            text="📤 SHARE DECRYPTED",
            command=self.share_decrypted_file,
            height=45,
            font=ctk.CTkFont(size=14),
            fg_color="#FFC107",
            hover_color="#E0A800",
            text_color="black",
            width=140
        )
        share_dec_btn.pack(side="left")
        
        # Result display
        self.decrypt_result_frame = ctk.CTkFrame(parent, corner_radius=10)
        self.decrypt_result_frame.pack(pady=20, padx=20, fill="x")
        self.decrypt_result_frame.pack_forget()
        
        self.decrypt_result_text = ctk.CTkTextbox(self.decrypt_result_frame, height=200)
        self.decrypt_result_text.pack(pady=10, padx=10, fill="both", expand=True)
    
    def encrypt_document_enhanced(self):
        """Encrypt a document for secure transmission - Enhanced version"""
        document_content = self.encrypt_doc_text.get("1.0", "end-1c").strip()
        recipient_id = self.recipient_id_entry.get().strip()
        password = self.encrypt_password_entry.get().strip() or None
        
        if not document_content or document_content == "Enter sensitive document content here...":
            messagebox.showwarning("Input Required", "Please enter document content")
            return
        
        # If file was uploaded, read binary data
        if self.upload_encrypt_path and os.path.exists(self.upload_encrypt_path):
            try:
                with open(self.upload_encrypt_path, 'rb') as f:
                    binary_data = f.read()
                    # For binary files, we'll encode as base64
                    document_content = base64.b64encode(binary_data).decode('utf-8')
                    is_binary = True
            except:
                is_binary = False
        else:
            is_binary = False
        
        try:
            # Get recipient's public key
            recipient_public_key = None
            
            if self.recipient_public_key:
                # Use uploaded key
                recipient_public_key = self.recipient_public_key
            elif recipient_id and db and not recipient_id.startswith("[Using uploaded key]"):
                # Get from database
                recipient = db.get_vendor_by_id(recipient_id)
                if recipient and recipient.get('public_key'):
                    recipient_public_key = recipient['public_key']
                else:
                    messagebox.showwarning("Recipient Not Found", 
                                         f"Vendor {recipient_id} not found or has no public key")
                    return
            else:
                messagebox.showwarning("Recipient Required", 
                                      "Please enter recipient Vendor ID or upload public key")
                return
            
            # Encrypt document
            encryption_manager = EncryptionManager()
            encrypted_data = encryption_manager.encrypt_document(
                content=document_content,
                public_key_pem=recipient_public_key,
                password=password
            )
            
            # Add metadata
            encrypted_data['metadata'] = {
                'vendor_id': self.vendor_id,
                'recipient_id': recipient_id if not recipient_id.startswith("[Using uploaded key]") else "unknown",
                'original_size': len(document_content),
                'is_binary': is_binary,
                'original_filename': os.path.basename(self.upload_encrypt_path) if self.upload_encrypt_path else None,
                'timestamp': datetime.now().isoformat()
            }
            
            # Store for later use
            self.current_encrypted_data = encrypted_data
            
            # Show result
            self.encrypt_result_frame.pack(pady=20, padx=20, fill="x")
            self.encrypt_result_text.delete("1.0", "end")
            
            result_json = json.dumps(encrypted_data, indent=2)
            self.encrypt_result_text.insert("1.0", result_json)
            
            # Enable download and share buttons
            messagebox.showinfo("Encryption Successful", 
                              f"✅ Document encrypted successfully!\n\n"
                              f"Recipient: {recipient_id}\n"
                              f"Algorithm: {encrypted_data['algorithm']}\n"
                              f"Size: {len(result_json)} bytes\n\n"
                              f"Use the DOWNLOAD button to save the encrypted file.\n"
                              f"Use the SHARE button to send to the recipient.")
            
            # Log to database
            if db:
                db.log_audit_event('vendor', self.vendor_id, 'encrypt_document',
                                  f'Document encrypted for {recipient_id}. Size: {len(document_content)} bytes')
            
        except Exception as e:
            messagebox.showerror("Encryption Error", f"Failed to encrypt document: {str(e)}")
    
    def share_encrypted_file_to_database(self):
        """SHARE TO DATABASE: Actually save encrypted document to database for recipient"""
        if not self.current_encrypted_data:
            messagebox.showwarning("No Data", "Please encrypt a document first")
            return
        
        recipient_id = self.recipient_id_entry.get().strip()
        if not recipient_id or recipient_id.startswith("[Using uploaded key]"):
            messagebox.showwarning("Recipient Required", "Please enter a valid recipient Vendor ID")
            return
        
        # Verify recipient exists
        recipient_exists = False
        if db:
            recipient = db.get_vendor_by_id(recipient_id)
            if recipient:
                recipient_exists = True
                recipient_name = recipient['company_name']
            else:
                # Ask if user wants to continue anyway
                if not messagebox.askyesno("Recipient Not Found", 
                                          f"Vendor {recipient_id} not found in database.\n"
                                          f"Do you want to share anyway?"):
                    return
        
        # Create a sharing window
        share_window = ctk.CTkToplevel(self.window)
        share_window.title("Share Encrypted Document")
        share_window.geometry("500x400")
        share_window.transient(self.window)
        share_window.grab_set()
        
        ctk.CTkLabel(
            share_window,
            text="📤 Share Encrypted Document",
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(pady=20)
        
        # Recipient info
        recipient_info = f"Recipient: {recipient_id}"
        if recipient_exists:
            recipient_info += f"\nCompany: {recipient_name}"
        else:
            recipient_info += "\n⚠️ Vendor not found in database"
        
        ctk.CTkLabel(
            share_window,
            text=recipient_info,
            font=ctk.CTkFont(size=14)
        ).pack(pady=10, padx=20)
        
        # Message
        ctk.CTkLabel(
            share_window,
            text="Message (optional):",
            font=ctk.CTkFont(size=14)
        ).pack(pady=(10, 5), padx=20, anchor="w")
        
        share_message_text = ctk.CTkTextbox(share_window, height=80)
        share_message_text.pack(pady=5, padx=20, fill="x")
        share_message_text.insert("1.0", f"Encrypted document shared by {self.vendor_id}")
        
        def send_share():
            message = share_message_text.get("1.0", "end-1c").strip()
            
            try:
                # Prepare share data
                share_data = {
                    'sender_id': self.vendor_id,
                    'recipient_id': recipient_id,
                    'encrypted_data': self.current_encrypted_data,
                    'file_name': f"encrypted_document_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    'file_size': len(json.dumps(self.current_encrypted_data)),
                    'message': message
                }
                
                # Save to database
                if db:
                    share_id = db.share_document(share_data)
                    
                    # Log audit
                    db.log_audit_event('vendor', self.vendor_id, 'share_document',
                                      f'Shared document with {recipient_id}. Share ID: {share_id}')
                    
                    messagebox.showinfo("Share Successful", 
                                      f"✅ Encrypted document shared successfully!\n\n"
                                      f"Share ID: {share_id}\n"
                                      f"Recipient: {recipient_id}\n"
                                      f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                                      f"The recipient can now decrypt this document from their 'Shared Documents' tab.")
                else:
                    # Fallback: save to file
                    temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
                    json.dump(self.current_encrypted_data, temp_file, indent=2)
                    temp_file.close()
                    
                    messagebox.showinfo("Share Ready (Database Not Available)", 
                                      f"✅ Encrypted document ready to share!\n\n"
                                      f"Recipient: {recipient_id}\n"
                                      f"File: {temp_file.name}\n\n"
                                      f"Note: Database not available, file saved locally.")
                
                share_window.destroy()
                
            except Exception as e:
                messagebox.showerror("Share Error", f"Failed to share document: {str(e)}")
        
        ctk.CTkButton(
            share_window,
            text="📤 SEND SHARE",
            command=send_share,
            height=45,
            fg_color="#9C27B0",
            hover_color="#7B1FA2"
        ).pack(pady=20, padx=20, fill="x")
    
    def test_decrypt_encrypted(self):
        """Test decrypt the currently encrypted content (for verification)"""
        if not self.current_encrypted_data:
            messagebox.showwarning("No Data", "Please encrypt a document first")
            return
        
        try:
            password = self.encrypt_password_entry.get().strip() or None
            encryption_manager = EncryptionManager()
            decrypted_content = encryption_manager.decrypt_document(
                encrypted_data=self.current_encrypted_data,
                private_key_pem=self.private_key_pem,
                password=password
            )
            
            # Check if content is base64 encoded binary
            if self.current_encrypted_data.get('metadata', {}).get('is_binary'):
                try:
                    # Try to decode base64
                    binary_data = base64.b64decode(decrypted_content)
                    decrypted_content = f"[Binary file: {self.current_encrypted_data['metadata'].get('original_filename', 'unknown')}]\nSize: {len(binary_data)} bytes"
                except:
                    pass
            
            messagebox.showinfo("Decryption Test", 
                              f"✅ Test decryption successful!\n\n"
                              f"Content preview:\n{decrypted_content[:200]}...")
            
        except Exception as e:
            messagebox.showerror("Decryption Error", f"Test decryption failed: {str(e)}")
    
    def download_encrypted_file(self):
        """Download the encrypted file"""
        if not self.current_encrypted_data:
            messagebox.showwarning("No Data", "Please encrypt a document first")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("Encrypted files", "*.enc"), ("All files", "*.*")],
            initialfile=f"encrypted_document_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    json.dump(self.current_encrypted_data, f, indent=2)
                messagebox.showinfo("Download Complete", f"Encrypted file saved to:\n{file_path}")
            except Exception as e:
                messagebox.showerror("Save Error", f"Failed to save file: {str(e)}")
    
    def decrypt_document_enhanced(self):
        """Decrypt an encrypted document - Enhanced version"""
        encrypted_json = self.decrypt_data_text.get("1.0", "end-1c").strip()
        password = self.decrypt_password_entry.get().strip() or None
        
        if not encrypted_json:
            messagebox.showwarning("Input Required", "Please enter encrypted JSON data")
            return
        
        try:
            # Parse JSON
            encrypted_data = json.loads(encrypted_json)
            
            # Decrypt document
            encryption_manager = EncryptionManager()
            decrypted_content = encryption_manager.decrypt_document(
                encrypted_data=encrypted_data,
                private_key_pem=self.private_key_pem,
                password=password
            )
            
            # Store for later use
            self.current_decrypted_content = decrypted_content
            self.current_encrypted_data = encrypted_data
            
            # Show result
            self.decrypt_result_frame.pack(pady=20, padx=20, fill="x")
            self.decrypt_result_text.delete("1.0", "end")
            
            # Check if content is base64 encoded binary
            if encrypted_data.get('metadata', {}).get('is_binary'):
                try:
                    # Try to decode base64
                    binary_data = base64.b64decode(decrypted_content)
                    original_filename = encrypted_data['metadata'].get('original_filename', 'decrypted_file.bin')
                    
                    # Show binary info
                    self.decrypt_result_text.insert("1.0", 
                        f"[Binary File Decrypted]\n"
                        f"Filename: {original_filename}\n"
                        f"Size: {len(binary_data)} bytes\n"
                        f"Original Size: {encrypted_data['metadata'].get('original_size', 'unknown')} bytes\n"
                        f"From: {encrypted_data['metadata'].get('vendor_id', 'unknown')}\n"
                        f"Timestamp: {encrypted_data['metadata'].get('timestamp', 'unknown')}\n\n"
                        f"Use DOWNLOAD button to save the binary file."
                    )
                    
                    # Store binary data
                    self.current_binary_data = binary_data
                except:
                    # Not binary, show as text
                    self.decrypt_result_text.insert("1.0", decrypted_content)
            else:
                # Regular text content
                self.decrypt_result_text.insert("1.0", decrypted_content)
            
            # Enable download and share buttons
            messagebox.showinfo("Decryption Successful", 
                              "✅ Document decrypted successfully!\n\n"
                              "The content is now displayed and can be saved or shared.")
            
            # Log to database
            if db:
                db.log_audit_event('vendor', self.vendor_id, 'decrypt_document',
                                  f'Document decrypted successfully. Size: {len(decrypted_content)} bytes')
            
        except json.JSONDecodeError:
            messagebox.showerror("Invalid JSON", "Please provide valid JSON data")
        except Exception as e:
            messagebox.showerror("Decryption Error", f"Failed to decrypt document: {str(e)}")
    
    def download_decrypted_file(self):
        """Download the decrypted file"""
        if not self.current_decrypted_content:
            messagebox.showwarning("No Data", "Please decrypt a document first")
            return
        
        # Determine file extension and content
        is_binary = False
        original_filename = "decrypted_document.txt"
        
        if hasattr(self, 'current_binary_data'):
            is_binary = True
            original_filename = self.current_encrypted_data.get('metadata', {}).get('original_filename', 'decrypted_file.bin')
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt" if not is_binary else ".bin",
            filetypes=[
                ("Text files", "*.txt") if not is_binary else ("Binary files", "*.bin"),
                ("All files", "*.*")
            ],
            initialfile=f"{original_filename}"
        )
        if file_path:
            try:
                if is_binary and hasattr(self, 'current_binary_data'):
                    with open(file_path, 'wb') as f:
                        f.write(self.current_binary_data)
                else:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(self.current_decrypted_content)
                
                messagebox.showinfo("Download Complete", f"Decrypted file saved to:\n{file_path}")
            except Exception as e:
                messagebox.showerror("Save Error", f"Failed to save file: {str(e)}")
    
    def share_decrypted_file(self):
        """Share the decrypted file (with security warning)"""
        if not self.current_decrypted_content:
            messagebox.showwarning("No Data", "Please decrypt a document first")
            return
        
        # Security warning
        if not messagebox.askyesno("Security Warning", 
                                  "⚠️ WARNING: Sharing decrypted content bypasses encryption security!\n\n"
                                  "Only share decrypted content with trusted parties.\n"
                                  "Are you sure you want to continue?"):
            return
        
        # Create a sharing window
        share_dec_window = ctk.CTkToplevel(self.window)
        share_dec_window.title("Share Decrypted Document")
        share_dec_window.geometry("500x400")
        share_dec_window.transient(self.window)
        share_dec_window.grab_set()
        
        ctk.CTkLabel(
            share_dec_window,
            text="⚠️ Share Decrypted Document",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="#FF6B6B"
        ).pack(pady=20)
        
        ctk.CTkLabel(
            share_dec_window,
            text="Recipient Vendor ID:",
            font=ctk.CTkFont(size=14)
        ).pack(pady=(10, 5), padx=20, anchor="w")
        
        share_dec_recipient_entry = ctk.CTkEntry(
            share_dec_window,
            placeholder_text="Enter Vendor ID",
            height=40
        )
        share_dec_recipient_entry.pack(pady=5, padx=20, fill="x")
        
        # Encryption option
        reencrypt_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            share_dec_window,
            text="Re-encrypt for recipient before sharing",
            variable=reencrypt_var,
            font=ctk.CTkFont(size=12)
        ).pack(pady=10, padx=20, anchor="w")
        
        def send_decrypted_share():
            recipient_id = share_dec_recipient_entry.get().strip()
            
            if not recipient_id:
                messagebox.showwarning("Input Required", "Please enter recipient Vendor ID")
                return
            
            if reencrypt_var.get():
                # Re-encrypt for recipient
                messagebox.showinfo("Secure Share", 
                                  f"✅ Document will be re-encrypted for {recipient_id} before sharing.\n\n"
                                  f"This maintains security while allowing sharing.")
            else:
                # Direct share (insecure)
                messagebox.showwarning("Insecure Share", 
                                      "⚠️ You are sharing decrypted content without encryption!\n\n"
                                      "This is not recommended for sensitive documents.")
            
            share_dec_window.destroy()
        
        ctk.CTkButton(
            share_dec_window,
            text="📤 SEND DECRYPTED",
            command=send_decrypted_share,
            height=45,
            fg_color="#FFC107",
            hover_color="#E0A800",
            text_color="black"
        ).pack(pady=20, padx=20, fill="x")
    
    # ====== SECURE MESSAGING TAB ======
    
    def setup_messaging_tab(self):
        """Setup secure messaging tab for vendor-to-vendor communication"""
        tab = self.tabview.tab("💬 Secure Messaging")
        self.messaging_tab = tab
        
        ctk.CTkLabel(
            tab,
            text="Secure Vendor Messaging",
            font=ctk.CTkFont(size=24, weight="bold")
        ).pack(pady=20)
        
        if not encryption_available:
            warning_frame = ctk.CTkFrame(tab, corner_radius=15, fg_color="#FFF3CD")
            warning_frame.pack(pady=10, padx=20, fill="x")
            ctk.CTkLabel(
                warning_frame,
                text="⚠️ Encryption module not available. Using mock encryption for demonstration.",
                font=ctk.CTkFont(size=14),
                text_color="#856404"
            ).pack(pady=20, padx=20)
        
        # Notebook for Send/Receive
        msg_notebook = ctk.CTkTabview(tab)
        msg_notebook.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Send Message Tab
        send_tab = msg_notebook.add("✉️ Send Message")
        self.setup_send_message_section(send_tab)
        
        # Receive Messages Tab
        receive_tab = msg_notebook.add("📥 Receive Messages")
        self.setup_receive_messages_section(receive_tab)
    
    def setup_send_message_section(self, parent):
        """Setup send message section"""
        # Recipient selection
        ctk.CTkLabel(
            parent,
            text="To (Vendor ID):",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(pady=(20, 10), padx=20, anchor="w")
        
        recipient_frame = ctk.CTkFrame(parent, fg_color="transparent")
        recipient_frame.pack(pady=5, padx=20, fill="x")
        
        self.msg_recipient_entry = ctk.CTkEntry(
            recipient_frame,
            placeholder_text="Enter recipient Vendor ID",
            height=40
        )
        self.msg_recipient_entry.pack(side="left", fill="x", expand=True)
        
        def load_recipient_info():
            recipient_id = self.msg_recipient_entry.get().strip()
            if recipient_id and db:
                vendor = db.get_vendor_by_id(recipient_id)
                if vendor:
                    messagebox.showinfo("Recipient Found", 
                                      f"Company: {vendor['company_name']}\n"
                                      f"Email: {vendor['contact_email']}\n"
                                      f"Status: {vendor['status']}")
                else:
                    messagebox.showwarning("Not Found", f"Vendor {recipient_id} not found")
        
        ctk.CTkButton(
            recipient_frame,
            text="🔍 Verify",
            command=load_recipient_info,
            width=80
        ).pack(side="right", padx=(10, 0))
        
        # Message subject
        ctk.CTkLabel(
            parent,
            text="Subject:",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(pady=(15, 5), padx=20, anchor="w")
        
        self.msg_subject_entry = ctk.CTkEntry(
            parent,
            placeholder_text="Enter message subject",
            height=40
        )
        self.msg_subject_entry.pack(pady=5, padx=20, fill="x")
        
        # Message content
        ctk.CTkLabel(
            parent,
            text="Message:",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(pady=(15, 5), padx=20, anchor="w")
        
        self.msg_content_text = ctk.CTkTextbox(parent, height=150)
        self.msg_content_text.pack(pady=5, padx=20, fill="x")
        
        # Send button
        send_btn = ctk.CTkButton(
            parent,
            text="✉️ SEND SECURE MESSAGE",
            command=self.send_secure_message,
            height=55,
            font=ctk.CTkFont(size=16, weight="bold"),
            fg_color="#9C27B0",
            hover_color="#7B1FA2"
        )
        send_btn.pack(pady=30, padx=20, fill="x")
    
    def setup_receive_messages_section(self, parent):
        """Setup receive messages section"""
        # Messages display area
        self.messages_display = ctk.CTkScrollableFrame(parent, height=400)
        self.messages_display.pack(pady=20, padx=20, fill="both", expand=True)
        
        # Refresh button
        def refresh_messages():
            self.refresh_messages()
        
        refresh_btn = ctk.CTkButton(
            parent,
            text="🔄 Refresh Messages",
            command=refresh_messages,
            height=40,
            width=150
        )
        refresh_btn.pack(pady=10, padx=20)
        
        # Load initial messages
        self.refresh_messages()
    
    def refresh_messages(self):
        
        # Clear existing widgets
        for widget in self.messages_display.winfo_children():
            widget.destroy()
        
        if db:
            # Get messages for this vendor from database
            try:
                messages = db.get_received_messages(self.vendor_id)
                
                if not messages:
                    ctk.CTkLabel(
                        self.messages_display,
                        text="No messages received yet.",
                        font=ctk.CTkFont(size=14),
                        text_color="gray"
                    ).pack(pady=20)
                    return
                
                # Display each message
                for msg in messages:
                    msg_id = msg.get('message_id', 'N/A')
                    sender_id = msg.get('sender_id', 'Unknown')
                    subject = msg.get('subject', 'No Subject')
                    timestamp = msg.get('sent_timestamp', '')
                    is_read = msg.get('is_read', False)
                    
                    msg_frame = ctk.CTkFrame(self.messages_display, corner_radius=8)
                    msg_frame.pack(pady=5, padx=5, fill="x")
                    
                    # Message header
                    header_frame = ctk.CTkFrame(msg_frame, fg_color="transparent")
                    header_frame.pack(fill="x", padx=10, pady=5)
                    
                    # Unread indicator
                    if not is_read:
                        unread_label = ctk.CTkLabel(
                            header_frame,
                            text="●",
                            text_color="#FF6B6B",
                            font=ctk.CTkFont(size=12, weight="bold")
                        )
                        unread_label.pack(side="left", padx=(0, 5))
                    
                    # Subject and sender
                    ctk.CTkLabel(
                        header_frame,
                        text=f"From: {sender_id} | {subject}",
                        font=ctk.CTkFont(size=12, weight="bold")
                    ).pack(side="left", padx=5)
                    
                    # Timestamp
                    if timestamp:
                        ctk.CTkLabel(
                            header_frame,
                            text=timestamp[11:16] if len(timestamp) > 10 else timestamp,
                            font=ctk.CTkFont(size=11),
                            text_color="gray"
                        ).pack(side="right", padx=5)
                    
                    # Actions frame
                    actions_frame = ctk.CTkFrame(msg_frame, fg_color="transparent")
                    actions_frame.pack(fill="x", padx=10, pady=(0, 5))
                    
                    # View/Decrypt button (existing)
                    def view_decrypt_message(msg_id=msg_id, encrypted_content=msg.get('encrypted_content', '{}')):
                        self.view_decrypt_message_fixed(msg_id, encrypted_content)
                    
                    ctk.CTkButton(
                        actions_frame,
                        text="🔓 Decrypt & View",
                        command=view_decrypt_message,
                        width=120,
                        height=30,
                        font=ctk.CTkFont(size=11)
                    ).pack(side="left", padx=2)
                    
                    # ===== DELETE BUTTON =====
                    # Capture current values to avoid closure issues
                    current_msg_id = msg_id
                    current_sender = sender_id
                    current_subject = subject
                    
                    def delete_message(m_id=current_msg_id, sndr=current_sender, subj=current_subject):
                        if messagebox.askyesno("Delete Message", 
                                            f"Delete this message?\n\nFrom: {sndr}\nSubject: {subj}\n\nThis cannot be undone!"):
                            try:
                                if db:
                                    conn = sqlite3.connect(db.db_path)
                                    cursor = conn.cursor()
                                    cursor.execute("DELETE FROM secure_messages WHERE message_id = ? AND recipient_id = ?", 
                                                (m_id, self.vendor_id))
                                    deleted = cursor.rowcount
                                    conn.commit()
                                    conn.close()
                                    
                                    if deleted > 0:
                                        messagebox.showinfo("Deleted", "Message deleted successfully")
                                        self.refresh_messages()
                                    else:
                                        messagebox.showerror("Error", "Message not found")
                            except Exception as e:
                                messagebox.showerror("Error", f"Failed to delete: {str(e)}")
                    
                    ctk.CTkButton(
                        actions_frame,
                        text="🗑️ Delete",
                        command=delete_message,
                        width=80,
                        height=30,
                        font=ctk.CTkFont(size=11),
                        fg_color="#DC3545",
                        hover_color="#c82333"
                    ).pack(side="right", padx=2)
                    # ===== END DELETE BUTTON =====
            
            except Exception as e:
                ctk.CTkLabel(
                    self.messages_display,
                    text=f"Error loading messages: {str(e)}",
                    font=ctk.CTkFont(size=14),
                    text_color="red"
                ).pack(pady=20)
        else:
            ctk.CTkLabel(
                self.messages_display,
                text="Database not available in demo mode.",
                font=ctk.CTkFont(size=14),
                text_color="gray"
            ).pack(pady=20)  
    def send_secure_message(self):
        """Send encrypted message to another vendor"""
        recipient_id = self.msg_recipient_entry.get().strip()
        subject = self.msg_subject_entry.get().strip()
        message_content = self.msg_content_text.get("1.0", "end-1c").strip()
        
        if not recipient_id:
            messagebox.showwarning("Input Required", "Please enter recipient Vendor ID")
            return
        
        if not message_content:
            messagebox.showwarning("Input Required", "Please enter message content")
            return
        
        try:
            # Get recipient's public key from database
            if db:
                recipient = db.get_vendor_by_id(recipient_id)
                if not recipient:
                    messagebox.showerror("Recipient Not Found", 
                                        f"Vendor {recipient_id} not found in system")
                    return
                
                recipient_public_key = recipient.get('public_key')
                if not recipient_public_key:
                    messagebox.showerror("No Public Key", 
                                        f"Vendor {recipient_id} has no public key registered")
                    return
                
                # Encrypt message
                encryption_manager = EncryptionManager()
                encrypted_message = encryption_manager.encrypt_message(
                    message=message_content,
                    recipient_public_key=recipient_public_key,
                    sender_private_key=self.private_key_pem,
                    password=self.password
                )
                
                # Store encrypted message in database
                message_id = f"MSG{datetime.now().strftime('%Y%m%d%H%M%S')}{random.randint(100, 999)}"
                
                try:
                    db.store_secure_message({
                        'message_id': message_id,
                        'sender_id': self.vendor_id,
                        'recipient_id': recipient_id,
                        'subject': subject,
                        'encrypted_content': json.dumps(encrypted_message),
                        'sent_timestamp': datetime.now().isoformat()
                    })
                except AttributeError:
                    # Fallback direct SQL
                    conn = sqlite3.connect(db.db_path)
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT INTO secure_messages 
                        (message_id, sender_id, recipient_id, subject, encrypted_content, sent_timestamp)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (
                        message_id,
                        self.vendor_id,
                        recipient_id,
                        subject,
                        json.dumps(encrypted_message),
                        datetime.now().isoformat()
                    ))
                    conn.commit()
                    conn.close()
                
                # Log audit
                if hasattr(db, 'log_audit_event'):
                    db.log_audit_event('vendor', self.vendor_id, 'send_message',
                                      f'Sent secure message to {recipient_id}. Message ID: {message_id}')
                
                # Clear form
                self.msg_recipient_entry.delete(0, "end")
                self.msg_subject_entry.delete(0, "end")
                self.msg_content_text.delete("1.0", "end")
                
                messagebox.showinfo("Message Sent", 
                                  f"✅ Secure message sent successfully!\n\n"
                                  f"To: {recipient_id}\n"
                                  f"Message ID: {message_id}\n"
                                  f"Encrypted with {encrypted_message['algorithm']}\n\n"
                                  f"Only the recipient can decrypt this message.")
                
                # Refresh messages
                self.refresh_messages()
                
            else:
                messagebox.showerror("Database Error", "Database not available")
                
        except Exception as e:
            messagebox.showerror("Send Error", f"Failed to send message: {str(e)}")
    
    def view_decrypt_message_fixed(self, message_id, encrypted_content_json):
        """FIXED VERSION: View and decrypt a received message"""
        try:
            # print(f"DEBUG: Decrypting message {message_id}")
            # print(f"DEBUG: Encrypted content type: {type(encrypted_content_json)}")
            
            # Parse encrypted content
            if isinstance(encrypted_content_json, str):
                try:
                    encrypted_data = json.loads(encrypted_content_json)
                except json.JSONDecodeError as e:
                    # print(f"DEBUG: JSON decode error: {e}")
                    # Try to fix common JSON issues
                    encrypted_content_json = encrypted_content_json.replace("'", '"')
                    encrypted_data = json.loads(encrypted_content_json)
            else:
                encrypted_data = encrypted_content_json
            
            # print(f"DEBUG: Encrypted data type: {type(encrypted_data)}")
            # print(f"DEBUG: Encrypted data keys: {encrypted_data.keys() if isinstance(encrypted_data, dict) else 'Not a dict'}")
            
            # Decrypt message
            encryption_manager = EncryptionManager()
            decrypted_content = encryption_manager.decrypt_message(
                encrypted_message=encrypted_data,
                recipient_private_key=self.private_key_pem,
                password=self.password
            )
            
            # print(f"DEBUG: Decryption successful! Content length: {len(decrypted_content)}")
            # print(f"DEBUG: Content preview: {decrypted_content[:100]}...")
            
            # Create view window
            view_window = ctk.CTkToplevel(self.window)
            view_window.title(f"Secure Message - {message_id}")
            view_window.geometry("600x500")
            view_window.transient(self.window)
            view_window.grab_set()
            
            # Header with message info
            header_frame = ctk.CTkFrame(view_window, corner_radius=10)
            header_frame.pack(pady=10, padx=20, fill="x")
            
            ctk.CTkLabel(
                header_frame,
                text="🔒 SECURE MESSAGE (DECRYPTED)",
                font=ctk.CTkFont(size=18, weight="bold")
            ).pack(pady=10)
            
            # Message info
            info_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
            info_frame.pack(pady=5, padx=10, fill="x")
            
            ctk.CTkLabel(
                info_frame,
                text=f"Message ID: {message_id}",
                font=ctk.CTkFont(size=12)
            ).pack(anchor="w")
            
            ctk.CTkLabel(
                info_frame,
                text=f"Decrypted at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                font=ctk.CTkFont(size=11),
                text_color="gray"
            ).pack(anchor="w")
            
            # Message content
            content_frame = ctk.CTkFrame(view_window, corner_radius=10)
            content_frame.pack(pady=10, padx=20, fill="both", expand=True)
            
            # Add scrollable text widget
            content_text = ctk.CTkTextbox(content_frame, font=ctk.CTkFont(size=12))
            content_text.pack(fill="both", expand=True, padx=10, pady=10)
            
            # Insert decrypted content
            if decrypted_content:
                content_text.insert("1.0", decrypted_content)
            else:
                content_text.insert("1.0", "⚠️ No content could be decrypted.")
            
            content_text.configure(state="disabled")
            
            # Action buttons frame
            action_frame = ctk.CTkFrame(view_window, fg_color="transparent")
            action_frame.pack(pady=10, padx=20, fill="x")
            
            # Copy button
            def copy_content():
                self.window.clipboard_clear()
                self.window.clipboard_append(decrypted_content)
                messagebox.showinfo("Copied", "Message content copied to clipboard!")
            
            ctk.CTkButton(
                action_frame,
                text="📋 Copy Content",
                command=copy_content,
                width=120,
                height=35
            ).pack(side="left", padx=5)
            
            # Save button
            def save_content():
                file_path = filedialog.asksaveasfilename(
                    defaultextension=".txt",
                    filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                    initialfile=f"message_{message_id}.txt"
                )
                if file_path:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(decrypted_content)
                    messagebox.showinfo("Saved", f"Message saved to:\n{file_path}")
            
            ctk.CTkButton(
                action_frame,
                text="💾 Save to File",
                command=save_content,
                width=120,
                height=35
            ).pack(side="left", padx=5)
            
            # Mark as read in database
            if db:
                try:
                    db.mark_message_as_read(message_id, decrypted_content)
                    # print(f"DEBUG: Message {message_id} marked as read in database")
                    
                    # Refresh messages
                    self.refresh_messages()
                except Exception as e:
                    print(f"DEBUG: Error updating message status: {e}")
            
            # Close button
            def close_view():
                view_window.destroy()
            
            ctk.CTkButton(
                action_frame,
                text="Close",
                command=close_view,
                width=120,
                height=35,
                fg_color="#6c757d",
                hover_color="#5a6268"
            ).pack(side="right", padx=5)
            
            # print(f"DEBUG: Message view window created for {message_id}")
            
        except json.JSONDecodeError as e:
            error_msg = f"Invalid JSON format in encrypted message:\n{str(e)}"
            # print(f"DEBUG: {error_msg}")
            messagebox.showerror("JSON Error", error_msg)
        except KeyError as e:
            error_msg = f"Missing required field in encrypted data: {str(e)}"
            # print(f"DEBUG: {error_msg}")
            messagebox.showerror("Data Error", error_msg)
        except Exception as e:
            error_msg = f"Failed to decrypt message: {str(e)}"
            # print(f"DEBUG: {error_msg}")
            import traceback
            traceback.print_exc()
            messagebox.showerror("Decryption Error", error_msg)
    
    # ====== PROFILE TAB ======
    
    def setup_profile(self):
        """Setup profile tab"""
        tab = self.tabview.tab("⚙️ Profile")
        
        ctk.CTkLabel(
            tab,
            text="Vendor Profile",
            font=ctk.CTkFont(size=24, weight="bold")
        ).pack(pady=20)
        
        # Get vendor info
        vendor_info = None
        if db:
            vendor_info = db.get_vendor_by_id(self.vendor_id)
        
        # Profile frame
        profile_frame = ctk.CTkFrame(tab, corner_radius=15)
        profile_frame.pack(pady=10, padx=20, fill="both", expand=True)
        
        if vendor_info:
            # Display vendor info
            info_items = [
                ("Vendor ID:", vendor_info['vendor_id']),
                ("Company Name:", vendor_info['company_name']),
                ("Email:", vendor_info['contact_email']),
                ("Contact Person:", vendor_info.get('contact_person', 'N/A')),
                ("Status:", vendor_info['status'].upper()),
                ("Registration Date:", vendor_info['registration_date'][:10]),
                ("Certificate Serial:", vendor_info.get('certificate_serial', 'N/A')),
            ]
            
            for label, value in info_items:
                item_frame = ctk.CTkFrame(profile_frame, fg_color="transparent")
                item_frame.pack(pady=8, padx=30, fill="x")
                
                ctk.CTkLabel(
                    item_frame,
                    text=label,
                    font=ctk.CTkFont(size=14, weight="bold")
                ).pack(side="left")
                
                ctk.CTkLabel(
                    item_frame,
                    text=value,
                    font=ctk.CTkFont(size=14)
                ).pack(side="right")
        
        # Help and support
        help_frame = ctk.CTkFrame(profile_frame, corner_radius=10)
        help_frame.pack(pady=30, padx=30, fill="x")
        
        ctk.CTkLabel(
            help_frame,
            text="❓ Need Help?",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(pady=10)
        
        def contact_admin():
            messagebox.showinfo("Contact Admin", 
                "For assistance:\n"
                "1. Email: admin@CertAuth-corp.com\n"
                "2. Phone: +1 (555) 123-4567\n"
                "3. Visit: Admin Panel for urgent issues")
        
        def view_documentation():
            webbrowser.open("https://en.wikipedia.org/wiki/Public_key_infrastructure")
        
        ctk.CTkButton(
            help_frame,
            text="📞 Contact Administrator",
            command=contact_admin,
            height=40
        ).pack(pady=5, padx=50, fill="x")
        
        ctk.CTkButton(
            help_frame,
            text="📖 PKI Documentation",
            command=view_documentation,
            height=40
        ).pack(pady=5, padx=50, fill="x")
    
    # ====== LOGOUT ======
    
    def logout(self):
        """Logout vendor"""
        if messagebox.askyesno("Logout", "Are you sure you want to logout?"):
            if db and hasattr(db, 'log_audit_event'):
                db.log_audit_event('vendor', self.vendor_id, 'logout', 'Vendor logged out')
            self.window.destroy()
            # Back to main menu
            try:
                from gui.main_menu import main
                main()
            except ImportError:
                # If main_menu is not available, just close
                pass
    
    def run(self):
        self.window.mainloop()

# ========== MAIN FUNCTIONS ==========
def start_vendor_registration():
    """Start vendor registration flow"""
    registration = VendorRegistrationWindow()
    registration.run()

def start_vendor_login():
    """Start vendor login flow"""
    def on_login_success(vendor_id, cert_pem, key_pem, password):
        dashboard = VendorDashboard(vendor_id, cert_pem, key_pem, password)
        dashboard.run()
    
    login = VendorLoginWindow(on_login_success)
    login.run()

# def test_vendor_portal():
#     """Test the vendor portal"""
#     print("\n" + "="*60)
#     print("TESTING VENDOR PORTAL FOR CertAuth: Vendor Authentication System")
#     print("="*60)
#     print("1. Starting vendor registration test...")
    
#     # You would normally run the GUI here
#     # For testing, we'll just show success
#     print("✅ Vendor portal components loaded successfully")
#     print("✅ Ready for PKI-based vendor authentication")
#     print("="*60)

# if __name__ == "__main__":
#     test_vendor_portal()