# gui/main_menu.py
"""
GUI MAIN MENU for CertAuth: Vendor Authentication System
"""
import customtkinter as ctk
from tkinter import messagebox
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class MainMenu:
    def __init__(self):
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        self.window = ctk.CTk()
        self.window.title("CertAuth: Vendor Authentication System")
        self.window.geometry("900x700")
        self.window.resizable(False, False)
        
        self.center_window()
        self.setup_ui()
    
    def center_window(self):
        """Center window on screen"""
        self.window.update_idletasks()
        width = 900
        height = 700
        x = (self.window.winfo_screenwidth() // 2) - (width // 2)
        y = (self.window.winfo_screenheight() // 2) - (height // 2)
        self.window.geometry(f'{width}x{height}+{x}+{y}')
    
    def setup_ui(self):
        """Setup main menu interface"""
        # Main container
        main_container = ctk.CTkFrame(self.window, corner_radius=20)
        main_container.pack(fill="both", expand=True, padx=30, pady=30)
        
        # Header
        header_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        header_frame.pack(pady=(40, 20), fill="x")
        
        ctk.CTkLabel(
            header_frame,
            text="🔐 CertAuth",
            font=ctk.CTkFont(size=48, weight="bold")
        ).pack()
        
        ctk.CTkLabel(
            header_frame,
            text="Vendor Authentication System",
            font=ctk.CTkFont(size=24)
        ).pack(pady=(10, 5))
        
        ctk.CTkLabel(
            header_frame,
            text="ST6051CEM - Practical Cryptography Coursework",
            font=ctk.CTkFont(size=14),
            text_color="gray70"
        ).pack()
        
        # Divider
        ctk.CTkFrame(main_container, height=2, fg_color="gray30").pack(pady=30, padx=50, fill="x")
        
        # Use case description
        desc_frame = ctk.CTkFrame(main_container, corner_radius=15)
        desc_frame.pack(pady=10, padx=40, fill="x")
        
        ctk.CTkLabel(
            desc_frame,
            text="📋 Use Case: CertAuth Vendor Authentication System",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(pady=(15, 10), padx=20, anchor="w")
        
        use_case_text = """• PKI-based vendor registration and login
• Digitally sign and verify documents
• Secure encrypted vendor-to-vendor file sharing
• Complete audit trail for compliance"""
        
        ctk.CTkLabel(
            desc_frame,
            text=use_case_text,
            font=ctk.CTkFont(size=13),
            justify="left"
        ).pack(pady=(0, 15), padx=20, anchor="w")
        
        # Divider
        ctk.CTkFrame(main_container, height=2, fg_color="gray30").pack(pady=20, padx=50, fill="x")
        
        # Selection buttons frame
        buttons_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        buttons_frame.pack(pady=20, padx=40, fill="both", expand=True)
        
        # Admin Portal Button - LEFT SIDE
        admin_frame = ctk.CTkFrame(buttons_frame, fg_color="transparent")
        admin_frame.pack(side="left", fill="both", expand=True, padx=10)
        
        admin_btn = ctk.CTkButton(
            admin_frame,
            text="🔐\nADMIN PORTAL",
            command=self.open_admin_portal,
            height=200,
            font=ctk.CTkFont(size=20, weight="bold"),
            fg_color="#2C3E50",
            hover_color="#34495E",
            corner_radius=15,
            border_width=3,
            border_color="#1C2833"
        )
        admin_btn.pack(fill="both", expand=True)
        
        ctk.CTkLabel(
            admin_frame,
            text="• Manage vendors & certificates\n• Issue/revoke certificates\n• View audit logs\n• Generate reports",
            font=ctk.CTkFont(size=12),
            text_color="gray70",
            justify="left"
        ).pack(pady=(10, 0))
        
        # Vendor Portal Button - RIGHT SIDE  
        vendor_frame = ctk.CTkFrame(buttons_frame, fg_color="transparent")
        vendor_frame.pack(side="right", fill="both", expand=True, padx=10)
        
        vendor_btn = ctk.CTkButton(
            vendor_frame,
            text="🏭\nVENDOR PORTAL",
            command=self.open_vendor_portal,
            height=200,
            font=ctk.CTkFont(size=20, weight="bold"),
            fg_color="#27AE60",
            hover_color="#219653",
            corner_radius=15,
            border_width=3,
            border_color="#1E8449"
        )
        vendor_btn.pack(fill="both", expand=True)
        
        ctk.CTkLabel(
            vendor_frame,
            text="• Register with PKI\n• Certificate-based login\n• Sign quality documents\n• Verify documents",
            font=ctk.CTkFont(size=12),
            text_color="gray70",
            justify="left"
        ).pack(pady=(10, 0))
        
        # Bottom buttons
        bottom_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        bottom_frame.pack(fill="x", pady=(30, 0))
        
        # System Tests Button
        tests_btn = ctk.CTkButton(
            bottom_frame,
            text="🧪 Run System Tests",
            command=self.open_tests,
            height=50,
            font=ctk.CTkFont(size=16),
            fg_color="#E67E22",
            hover_color="#D35400",
            corner_radius=10
        )
        tests_btn.pack(side="left", padx=5, fill="x", expand=True)
        
        # Documentation Button
        docs_btn = ctk.CTkButton(
            bottom_frame,
            text="📖 Documentation",
            command=self.open_documentation,
            height=50,
            font=ctk.CTkFont(size=16),
            fg_color="#3498DB",
            hover_color="#2980B9",
            corner_radius=10
        )
        docs_btn.pack(side="left", padx=5, fill="x", expand=True)
        
        # Exit Button
        exit_btn = ctk.CTkButton(
            bottom_frame,
            text="🚪 Exit System",
            command=self.window.quit,
            height=50,
            font=ctk.CTkFont(size=16),
            fg_color="#E74C3C",
            hover_color="#C0392B",
            corner_radius=10
        )
        exit_btn.pack(side="left", padx=5, fill="x", expand=True)
        
        # Footer
        footer_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        footer_frame.pack(fill="x", pady=(20, 0))
        
        ctk.CTkLabel(
            footer_frame,
            text="PKI | Digital Signatures | Certificate Authentication | Vendor Management",
            font=ctk.CTkFont(size=10),
            text_color="gray60"
        ).pack()
    
    def open_admin_portal(self):
        """Open admin portal"""
        try:
            from gui.admin_panel import main as admin_main
            self.window.destroy()
            admin_main()
        except ImportError as e:
            messagebox.showerror("Error", f"Cannot load admin portal: {e}")
    
    def open_vendor_portal(self):
        """Open vendor portal selection"""
        selection_window = ctk.CTkToplevel(self.window)
        selection_window.title("Vendor Portal")
        selection_window.geometry("500x400")
        selection_window.resizable(False, False)
        selection_window.transient(self.window)
        selection_window.update_idletasks()
        selection_window.deiconify()
        selection_window.after(200, selection_window.grab_set)
        
        # Center
        selection_window.update_idletasks()
        x = self.window.winfo_x() + (self.window.winfo_width() // 2) - (500 // 2)
        y = self.window.winfo_y() + (self.window.winfo_height() // 2) - (400 // 2)
        selection_window.geometry(f"500x400+{x}+{y}")
        
        ctk.CTkLabel(
            selection_window,
            text="VENDOR PORTAL",
            font=ctk.CTkFont(size=24, weight="bold")
        ).pack(pady=30)
        
        # Registration button
        ctk.CTkButton(
            selection_window,
            text="📝 NEW VENDOR REGISTRATION",
            command=lambda: self.start_vendor_registration(selection_window),
            height=60,
            font=ctk.CTkFont(size=16, weight="bold"),
            fg_color="#27AE60",
            hover_color="#219653"
        ).pack(pady=15, padx=50, fill="x")
        
        ctk.CTkLabel(
            selection_window,
            text="Register new vendor with PKI (generate key pair + certificate)",
            font=ctk.CTkFont(size=11),
            text_color="gray70"
        ).pack(pady=(0, 20))
        
        # Login button
        ctk.CTkButton(
            selection_window,
            text="🔐 EXISTING VENDOR LOGIN",
            command=lambda: self.start_vendor_login(selection_window),
            height=60,
            font=ctk.CTkFont(size=16, weight="bold"),
            fg_color="#3498DB",
            hover_color="#2980B9"
        ).pack(pady=15, padx=50, fill="x")
        
        ctk.CTkLabel(
            selection_window,
            text="Login with digital certificate for document signing",
            font=ctk.CTkFont(size=11),
            text_color="gray70"
        ).pack(pady=(0, 20))
        
        # Back button
        ctk.CTkButton(
            selection_window,
            text="↩️ BACK TO MAIN MENU",
            command=selection_window.destroy,
            height=40,
            fg_color="transparent",
            hover_color=("gray70", "gray30")
        ).pack(pady=10)
    
    def start_vendor_registration(self, parent_window):
        """Start vendor registration"""
        try:
            from gui.vendor_portal import start_vendor_registration
            parent_window.destroy()
            self.window.destroy()
            start_vendor_registration()
        except ImportError as e:
            messagebox.showerror("Error", f"Cannot load vendor portal: {e}")
    
    def start_vendor_login(self, parent_window):
        """Start vendor login"""
        try:
            from gui.vendor_portal import start_vendor_login
            parent_window.destroy()
            self.window.destroy()
            start_vendor_login()
        except ImportError as e:
            messagebox.showerror("Error", f"Cannot load vendor portal: {e}")
    
    def open_tests(self):
        """Open tests window"""
        messagebox.showinfo("System Tests", 
            "System tests will be run in console.\n\n"
            "Please run from command line:\n"
            "python tests/security_tests.py\n\n"
            "Or check tests/ folder for test files.")
    
    def open_documentation(self):
        """Open documentation window"""
        docs_window = ctk.CTkToplevel(self.window)
        docs_window.title("Documentation")
        docs_window.geometry("700x600")
        docs_window.resizable(False, False)
        docs_window.transient(self.window)
        docs_window.after(200, docs_window.grab_set)
        
        # Center
        docs_window.update_idletasks()
        x = self.window.winfo_x() + (self.window.winfo_width() // 2) - (700 // 2)
        y = self.window.winfo_y() + (self.window.winfo_height() // 2) - (600 // 2)
        docs_window.geometry(f"700x600+{x}+{y}")
        
        # Text widget for documentation
        text_widget = ctk.CTkTextbox(docs_window, font=ctk.CTkFont(size=12))
        text_widget.pack(fill="both", expand=True, padx=20, pady=20)
        
        documentation = """CERTAUTH: VENDOR AUTHENTICATION SYSTEM
=====================================

COURSEWORK REQUIREMENTS COVERED:

1. USER AUTHENTICATION WITH PKI
   • Vendor registration with RSA key pair generation
   • X.509 digital certificate issuance by CA
   • Certificate-based authentication
   • Proof of private key possession

2. DOCUMENT SIGNING & VERIFICATION
   • Digital signatures using SHA-256 with PSS padding
   • Document hash generation for integrity
   • Signature verification with public keys
   • Non-repudiation of signed documents

3. SECURITY FEATURES
   • Confidentiality via encrypted private keys
   • Integrity via cryptographic hashing
   • Authentication via digital certificates
   • Certificate revocation (CRL)

4. KEY MANAGEMENT
   • Secure key generation (RSA 2048-bit)
   • Certificate Authority with chain validation
   • Certificate lifecycle management
   • Secure storage in SQLite database

5. USE CASE: VENDOR AUTHENTICATION
   • Quality certificate verification system
   • Vendor authentication for suppliers
   • Document non-repudiation for compliance
   • Audit trail for supply chain security

6. TESTING & VALIDATION
   • Unit tests for cryptographic functions
   • Security attack simulations (MITM, spoofing)
   • Integration tests for complete PKI flow
   • Database transaction testing

TECHNICAL ARCHITECTURE:
• Frontend: CustomTkinter GUI
• Cryptography: Python Cryptography library
• Database: SQLite with secure schema
• PKI: X.509 certificates with CRL support

PROJECT STRUCTURE:
CertAuth-System/
├── crypto/           # Cryptography engine
├── gui/             # User interfaces
├── auth/            # Authentication system
├── database/        # SQLite database
├── certs/           # Certificate storage
├── tests/           # Test suites
└── docs/            # Documentation"""
        
        text_widget.insert("1.0", documentation)
        text_widget.configure(state="disabled")
    
    def run(self):
        self.window.mainloop()

def main():
    """Main entry point for GUI"""
    app = MainMenu()
    app.run()

if __name__ == "__main__":
    main()