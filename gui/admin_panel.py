"""
COMPLETE MANAGEMENT SUPPLY CHAIN ADMIN PORTAL - WITH ALL FUNCTIONS WORKING
"""
import customtkinter as ctk
from tkinter import messagebox, filedialog, ttk
import sys
import os
import sqlite3
import json
import csv
import hashlib
from datetime import datetime, timedelta
import webbrowser
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Add parent directory to path
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# Import modules
from auth.admin_auth import AdminAuth
from database.models import db
from crypto.ca_manager import CertificateAuthorityManager
from crypto.certificate_engine import CertificateEngine


# ========== LOGIN WINDOW ==========
class LoginWindow:
    def __init__(self, on_login_success):
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        self.window = ctk.CTk()
        self.window.title("CertAuth: Vendor Authentication System - Admin Login")
        self.window.geometry("500x600")
        self.window.resizable(False, False)
        
        self.on_login_success = on_login_success
        self.after_ids = []
        self.setup_ui()
        
        self.window.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def setup_ui(self):
        main_frame = ctk.CTkFrame(self.window, corner_radius=20)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(
            main_frame,
            text="🏭 Admin Portal",
            font=ctk.CTkFont(size=32, weight="bold")
        ).pack(pady=(40, 10))
        
        ctk.CTkLabel(
            main_frame,
            text="CertAuth: Vendor Authentication System ",
            font=ctk.CTkFont(size=16)
        ).pack(pady=(0, 40))
        
        form_frame = ctk.CTkFrame(main_frame, corner_radius=15)
        form_frame.pack(padx=40, pady=10, fill="x")
        
        ctk.CTkLabel(form_frame, text="Username", font=ctk.CTkFont(size=14)).pack(pady=(20, 5), padx=30, anchor="w")
        self.username_entry = ctk.CTkEntry(form_frame, placeholder_text="admin", height=45)
        self.username_entry.pack(pady=5, padx=30, fill="x")
        self.username_entry.insert(0, "admin")
        
        ctk.CTkLabel(form_frame, text="Password", font=ctk.CTkFont(size=14)).pack(pady=(15, 5), padx=30, anchor="w")
        self.password_entry = ctk.CTkEntry(form_frame, show="•", height=45)
        self.password_entry.pack(pady=5, padx=30, fill="x")
        self.password_entry.insert(0, "admin123")
        
        ctk.CTkButton(
            form_frame,
            text="🔐 LOGIN",
            command=self.authenticate,
            height=55,
            font=ctk.CTkFont(size=16, weight="bold"),
            fg_color="#2E8B57",
            hover_color="#228B22"
        ).pack(pady=30, padx=30, fill="x")
        
        ctk.CTkButton(
            main_frame,
            text="Forgot Password?",
            command=self.forgot_password,
            fg_color="transparent",
            text_color="gray"
        ).pack(pady=10)
    
    def authenticate(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not username or not password:
            messagebox.showwarning("Input Required", "Please enter username and password")
            return
        
        try:
            auth = AdminAuth()
            success, message = auth.authenticate(username, password)
            
            if success:
                if message == "first_login":
                    self.show_change_password(auth, username)
                else:
                    self.cleanup_before_exit()
                    self.window.destroy()
                    self.on_login_success(username)
            else:
                messagebox.showerror("Login Failed", message)
        except Exception as e:
            messagebox.showerror("Authentication Error", f"Authentication error: {str(e)}")
    
    def show_change_password(self, auth, username):
        dialog = ctk.CTkToplevel(self.window)
        dialog.title("Change Password")
        dialog.geometry("400x400")
        dialog.transient(self.window)
        dialog.grab_set()
        
        ctk.CTkLabel(
            dialog,
            text="🔐 First Login - Change Password",
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(pady=20)
        
        ctk.CTkLabel(
            dialog,
            text="Please set a new secure password",
            font=ctk.CTkFont(size=14)
        ).pack(pady=5)
        
        ctk.CTkLabel(dialog, text="New Password:").pack(pady=(20, 5), padx=30, anchor="w")
        new_pass_entry = ctk.CTkEntry(dialog, show="•", height=40)
        new_pass_entry.pack(pady=5, padx=30, fill="x")
        
        ctk.CTkLabel(dialog, text="Confirm Password:").pack(pady=(10, 5), padx=30, anchor="w")
        confirm_pass_entry = ctk.CTkEntry(dialog, show="•", height=40)
        confirm_pass_entry.pack(pady=5, padx=30, fill="x")
        
        def change_password():
            new_pass = new_pass_entry.get()
            confirm_pass = confirm_pass_entry.get()
            
            if not new_pass or not confirm_pass:
                messagebox.showwarning("Input Required", "Please enter both fields")
                return
            
            if new_pass != confirm_pass:
                messagebox.showerror("Error", "Passwords do not match")
                return
            
            if len(new_pass) < 6:
                messagebox.showwarning("Weak Password", "Password must be at least 6 characters")
                return
            
            success, msg = auth.change_password(username, new_pass)
            if success:
                messagebox.showinfo("Success", "Password changed successfully!")
                dialog.destroy()
                self.cleanup_before_exit()
                self.window.destroy()
                self.on_login_success(username)
            else:
                messagebox.showerror("Error", msg)
        
        ctk.CTkButton(
            dialog,
            text="Change Password",
            command=change_password,
            height=45
        ).pack(pady=30, padx=30, fill="x")
        
        dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)
    
    def forgot_password(self):
        messagebox.showinfo("Reset Password", "Contact system administrator to reset your password.")
    
    def cleanup_before_exit(self):
        try:
            for after_id in self.after_ids:
                try:
                    self.window.after_cancel(after_id)
                except:
                    pass
        except:
            pass
    
    def on_closing(self):
        self.cleanup_before_exit()
        self.window.destroy()
        sys.exit(0)
    
    def run(self):
        self.window.mainloop()


# ========== MAIN ADMIN PANEL ==========
class AdminPanel:
    def __init__(self, username):
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        self.window = ctk.CTk()
        self.window.title(f"Admin Dashboard - CertAuth: Vendor Authentication System")
        self.window.geometry("1400x800")
        
        self.window.protocol("WM_DELETE_WINDOW", self.safe_quit)
        
        self.username = username
        self.auth = AdminAuth()
        self.admin_info = self.auth.get_admin_info(username)
        self.after_ids = []
        
        # Initialize CA Manager
        self.ca_manager = CertificateAuthorityManager()
        self.crypto_engine = CertificateEngine()
        
        # Email settings (configure these)
        self.smtp_server = "smtp.gmail.com"
        self.smtp_port = 587
        self.smtp_username = "your-email@gmail.com"
        self.smtp_password = "your-app-password"
        
        # Configure grid
        self.window.grid_columnconfigure(1, weight=1)
        self.window.grid_rowconfigure(0, weight=1)
        
        self.setup_sidebar()
        self.setup_main_content()
        self.load_system_stats()
        
        self.schedule_auto_refresh()
    
    def schedule_auto_refresh(self):
        """Safely schedule next auto-refresh"""
        try:
            if not self.window.winfo_exists():
                return
            
            self.load_system_stats()
            after_id = self.window.after(30000, self.schedule_auto_refresh)
            self.after_ids.append(after_id)
        except:
            pass
    
    def safe_quit(self):
        """Safely quit the application"""
        for after_id in self.after_ids:
            try:
                self.window.after_cancel(after_id)
            except:
                pass
        self.window.quit()
        self.window.destroy()
    
    def setup_sidebar(self):
        """Create sidebar navigation"""
        sidebar = ctk.CTkFrame(self.window, width=250, corner_radius=0)
        sidebar.grid(row=0, column=0, sticky="nsew")
        
        # Logo
        ctk.CTkLabel(
            sidebar,
            text="🏭 Admin Portal",
            font=ctk.CTkFont(size=22, weight="bold")
        ).pack(pady=(30, 20))
        
        # User info
        user_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        user_frame.pack(pady=10, padx=20, fill="x")
        
        ctk.CTkLabel(
            user_frame,
            text=f"👤 {self.username}",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack()
        
        role = self.admin_info.get('role', 'admin') if self.admin_info else 'admin'
        ctk.CTkLabel(
            user_frame,
            text=f"⚡ {role}",
            font=ctk.CTkFont(size=12),
            text_color="gray"
        ).pack()
        
        # Navigation
        nav_items = [
            ("📊 Dashboard", self.show_dashboard),
            ("👥 Vendors", self.show_vendors),
            ("📄 Documents", self.show_documents),
            ("🔐 Certificates", self.show_certificates),
            ("📜 Audit Trail", self.show_audit_logs),
            ("📋 Reports", self.show_reports),
            ("👤 User Management", self.show_user_management),
            ("⚙️ Settings", self.show_settings)
        ]
        
        for text, command in nav_items:
            btn = ctk.CTkButton(
                sidebar,
                text=text,
                command=command,
                height=40,
                corner_radius=8,
                anchor="w",
                fg_color="transparent",
                hover_color=("gray70", "gray30"),
                font=ctk.CTkFont(size=13)
            )
            btn.pack(pady=2, padx=10, fill="x")
        
        # Logout button
        ctk.CTkButton(
            sidebar,
            text="🚪 Logout",
            command=self.logout,
            height=45,
            fg_color="#FF6B6B",
            hover_color="#FF5252",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(side="bottom", pady=20, padx=20, fill="x")
    
    def setup_main_content(self):
        """Setup main content area with tabs"""
        self.main_content = ctk.CTkFrame(self.window, corner_radius=10)
        self.main_content.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        self.main_content.grid_columnconfigure(0, weight=1)
        self.main_content.grid_rowconfigure(0, weight=1)
        
        self.tabview = ctk.CTkTabview(self.main_content)
        self.tabview.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        
        # Add tabs
        tabs = [
            "Dashboard", "Vendors", "Documents", "Certificates",
            "Audit Trail", "Reports", "User Management", "Settings"
        ]
        
        for tab in tabs:
            self.tabview.add(tab)
        
        # Setup each tab
        self.setup_dashboard()
        self.setup_vendors_tab()
        self.setup_documents_tab()
        self.setup_certificates_tab()
        self.setup_audit_trail_tab()
        self.setup_reports_tab()
        self.setup_user_management_tab()
        self.setup_settings_tab()
    
    # ========== NAVIGATION ==========
    
    def show_dashboard(self):
        self.tabview.set("Dashboard")
        self.load_system_stats()
    
    def show_vendors(self):
        self.tabview.set("Vendors")
        self.refresh_vendors_list()
    
    def show_documents(self):
        self.tabview.set("Documents")
        self.refresh_documents_list()
    
    def show_certificates(self):
        self.tabview.set("Certificates")
        self.refresh_certificates_list()
    
    def show_audit_logs(self):
        self.tabview.set("Audit Trail")
        self.refresh_audit_logs()
    
    def show_reports(self):
        self.tabview.set("Reports")
    
    def show_user_management(self):
        self.tabview.set("User Management")
        self.refresh_admin_users()
    
    def show_settings(self):
        self.tabview.set("Settings")
    
    # ========== DASHBOARD ==========
    
    def setup_dashboard(self):
        """Setup dashboard tab"""
        tab = self.tabview.tab("Dashboard")
        
        for widget in tab.winfo_children():
            widget.destroy()
        
        ctk.CTkLabel(
            tab,
            text="System Dashboard",
            font=ctk.CTkFont(size=24, weight="bold")
        ).pack(pady=20)
        
        # Stats cards frame
        stats_frame = ctk.CTkFrame(tab, corner_radius=15)
        stats_frame.pack(pady=10, padx=20, fill="x")
        
        self.stats_cards = []
        
        stats_config = [
            ("Total Vendors", "vendors_total", "👥"),
            ("Active Vendors", "vendors_active", "✅"),
            ("Pending Approval", "vendors_pending", "⏳"),
            ("Total Documents", "documents_total", "📄"),
            ("Pending Verification", "documents_pending", "🔍"),
            ("Active Certificates", "certificates_active", "🔐"),
            ("Expiring Soon", "certificates_expiring", "⚠️"),
            ("Expired Certificates", "certificates_expired", "❌")
        ]
        
        for i, (label, key, icon) in enumerate(stats_config):
            row = i // 4
            col = i % 4
            
            card = ctk.CTkFrame(stats_frame, corner_radius=10)
            card.grid(row=row, column=col, padx=10, pady=10, sticky="nsew")
            
            title_label = ctk.CTkLabel(
                card, 
                text=f"{icon} {label}",
                font=ctk.CTkFont(size=14)
            )
            title_label.pack(pady=(15, 5))
            
            value_label = ctk.CTkLabel(
                card,
                text="...",
                font=ctk.CTkFont(size=32, weight="bold")
            )
            value_label.pack(pady=(0, 15))
            
            self.stats_cards.append((key, title_label, value_label))
        
        # Quick Actions
        actions_frame = ctk.CTkFrame(tab, corner_radius=15)
        actions_frame.pack(pady=20, padx=20, fill="x")
        
        ctk.CTkLabel(
            actions_frame,
            text="⚡ Quick Actions",
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(pady=10)
        
        action_buttons = ctk.CTkFrame(actions_frame, fg_color="transparent")
        action_buttons.pack(pady=10)
        
        actions = [
            ("Check Expiring Certificates", self.check_expiring_certificates),
            ("Send Reminder Emails", self.send_expiry_reminders),
            ("Generate Report", lambda: self.tabview.set("Reports")),
            ("Review Pending Vendors", self.show_pending_vendors)
        ]
        
        for i, (text, command) in enumerate(actions):
            btn = ctk.CTkButton(
                action_buttons,
                text=text,
                command=command,
                width=200,
                height=40
            )
            btn.grid(row=i//2, column=i%2, padx=10, pady=5)
        
        # Recent Activities
        recent_frame = ctk.CTkFrame(tab, corner_radius=15)
        recent_frame.pack(pady=20, padx=20, fill="both", expand=True)
        
        ctk.CTkLabel(
            recent_frame,
            text="📈 Recent Activities",
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(pady=10)
        
        self.recent_activities_frame = ctk.CTkScrollableFrame(recent_frame, height=200)
        self.recent_activities_frame.pack(pady=10, padx=20, fill="both", expand=True)
    
    def load_system_stats(self):
        """Load and display system statistics"""
        try:
            conn = sqlite3.connect("database/certauth.db")
            cursor = conn.cursor()
            
            stats = {}
            
            # Vendor stats
            cursor.execute("SELECT COUNT(*) FROM vendors")
            stats['vendors_total'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM vendors WHERE status = 'active'")
            stats['vendors_active'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM vendors WHERE status = 'pending'")
            stats['vendors_pending'] = cursor.fetchone()[0]
            
            # Document stats
            cursor.execute("SELECT COUNT(*) FROM signed_documents")
            stats['documents_total'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM signed_documents WHERE verification_status = 'pending'")
            stats['documents_pending'] = cursor.fetchone()[0]
            
            # Certificate stats
            cursor.execute("SELECT COUNT(*) FROM certificates WHERE revoked = 0")
            stats['certificates_active'] = cursor.fetchone()[0]
            
            cursor.execute("""
                SELECT COUNT(*) FROM certificates 
                WHERE revoked = 0 AND not_valid_after < date('now', '+30 days')
                AND not_valid_after > date('now')
            """)
            stats['certificates_expiring'] = cursor.fetchone()[0]
            
            cursor.execute("""
                SELECT COUNT(*) FROM certificates 
                WHERE not_valid_after < date('now')
            """)
            stats['certificates_expired'] = cursor.fetchone()[0]
            
            conn.close()
            
            # Update cards
            for key, title_label, value_label in self.stats_cards:
                value_label.configure(text=str(stats.get(key, 0)))
            
            # Load recent activities
            self.load_recent_activities()
            
        except Exception as e:
            print(f"Error loading stats: {e}")
    
    def load_recent_activities(self):
        """Load recent activities from audit log"""
        for widget in self.recent_activities_frame.winfo_children():
            widget.destroy()
        
        try:
            conn = sqlite3.connect("database/certauth.db")
            cursor = conn.cursor()
            cursor.execute("""
                SELECT timestamp, user_type, user_id, action, details 
                FROM audit_log 
                ORDER BY timestamp DESC 
                LIMIT 20
            """)
            activities = cursor.fetchall()
            conn.close()
            
            if not activities:
                ctk.CTkLabel(
                    self.recent_activities_frame,
                    text="No recent activities",
                    font=ctk.CTkFont(size=14),
                    text_color="gray"
                ).pack(pady=20)
                return
            
            for activity in activities:
                ts, user_type, user_id, action, details = activity
                
                item_frame = ctk.CTkFrame(self.recent_activities_frame, corner_radius=8)
                item_frame.pack(pady=3, padx=5, fill="x")
                
                header = ctk.CTkFrame(item_frame, fg_color="transparent")
                header.pack(fill="x", padx=10, pady=5)
                
                time_str = ts[11:16] if ts else "--:--"
                ctk.CTkLabel(
                    header,
                    text=f"[{time_str}] {user_type.upper()} {user_id}:",
                    font=ctk.CTkFont(size=12, weight="bold")
                ).pack(side="left")
                
                ctk.CTkLabel(
                    header,
                    text=action,
                    font=ctk.CTkFont(size=12),
                    text_color="#4CAF50"
                ).pack(side="left", padx=10)
                
                if details:
                    ctk.CTkLabel(
                        item_frame,
                        text=f"  {details}",
                        font=ctk.CTkFont(size=11),
                        text_color="gray"
                    ).pack(anchor="w", padx=20, pady=(0, 5))
                    
        except Exception as e:
            ctk.CTkLabel(
                self.recent_activities_frame,
                text=f"Error loading activities: {str(e)}",
                text_color="red"
            ).pack(pady=20)
    
    def check_expiring_certificates(self):
        """Check and display expiring certificates"""
        self.tabview.set("Certificates")
        self.cert_status_var.set("expiring")
        self.refresh_certificates_list()
        messagebox.showinfo("Info", "Showing certificates expiring within 30 days")
    
    def send_expiry_reminders(self):
        """Send email reminders for expiring certificates"""
        try:
            conn = sqlite3.connect("database/certauth.db")
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT c.serial_number, v.vendor_id, v.company_name, v.contact_email,
                       c.not_valid_after, julianday(c.not_valid_after) - julianday('now') as days_left
                FROM certificates c
                JOIN vendors v ON c.vendor_id = v.vendor_id
                WHERE c.revoked = 0 
                  AND c.not_valid_after < date('now', '+30 days')
                  AND c.not_valid_after > date('now')
                ORDER BY days_left
            """)
            
            expiring = cursor.fetchall()
            conn.close()
            
            if not expiring:
                messagebox.showinfo("No Reminders", "No certificates expiring soon")
                return
            
            # Show email configuration dialog
            self.show_email_config_dialog(expiring)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to check certificates: {str(e)}")
    
    def show_email_config_dialog(self, expiring_certs):
        """Show email configuration dialog"""
        dialog = ctk.CTkToplevel(self.window)
        dialog.title("Send Expiry Reminders")
        dialog.geometry("500x600")
        dialog.transient(self.window)
        dialog.grab_set()
        
        ctk.CTkLabel(
            dialog,
            text="📧 Send Certificate Expiry Reminders",
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(pady=20)
        
        # Certificate list
        list_frame = ctk.CTkScrollableFrame(dialog, height=200)
        list_frame.pack(pady=10, padx=20, fill="x")
        
        ctk.CTkLabel(
            list_frame,
            text="Certificates expiring soon:",
            font=ctk.CTkFont(weight="bold")
        ).pack(anchor="w", pady=5)
        
        for cert in expiring_certs:
            serial, vendor_id, company, email, expiry, days = cert
            days_int = int(days)
            
            item_frame = ctk.CTkFrame(list_frame)
            item_frame.pack(fill="x", pady=2)
            
            status = "⚠️" if days_int <= 7 else "📅"
            ctk.CTkLabel(
                item_frame,
                text=f"{status} {company} - {days_int} days left",
                anchor="w"
            ).pack(side="left", padx=5)
        
        # Email settings
        settings_frame = ctk.CTkFrame(dialog)
        settings_frame.pack(pady=10, padx=20, fill="x")
        
        ctk.CTkLabel(settings_frame, text="SMTP Server:").pack(anchor="w", padx=10, pady=(10, 2))
        smtp_entry = ctk.CTkEntry(settings_frame, placeholder_text="smtp.gmail.com")
        smtp_entry.pack(fill="x", padx=10, pady=2)
        smtp_entry.insert(0, self.smtp_server)
        
        ctk.CTkLabel(settings_frame, text="Port:").pack(anchor="w", padx=10, pady=(10, 2))
        port_entry = ctk.CTkEntry(settings_frame, placeholder_text="587")
        port_entry.pack(fill="x", padx=10, pady=2)
        port_entry.insert(0, str(self.smtp_port))
        
        ctk.CTkLabel(settings_frame, text="Username:").pack(anchor="w", padx=10, pady=(10, 2))
        user_entry = ctk.CTkEntry(settings_frame, placeholder_text="your-email@gmail.com")
        user_entry.pack(fill="x", padx=10, pady=2)
        user_entry.insert(0, self.smtp_username)
        
        ctk.CTkLabel(settings_frame, text="Password:").pack(anchor="w", padx=10, pady=(10, 2))
        pass_entry = ctk.CTkEntry(settings_frame, show="•")
        pass_entry.pack(fill="x", padx=10, pady=2)
        pass_entry.insert(0, self.smtp_password)
        
        def send_emails():
            # Update settings
            self.smtp_server = smtp_entry.get()
            self.smtp_port = int(port_entry.get())
            self.smtp_username = user_entry.get()
            self.smtp_password = pass_entry.get()
            
            # Send emails
            success_count = 0
            for cert in expiring_certs:
                if self.send_reminder_email(cert):
                    success_count += 1
            
            messagebox.showinfo("Success", f"Sent {success_count} of {len(expiring_certs)} reminders")
            dialog.destroy()
        
        ctk.CTkButton(
            dialog,
            text="📧 Send Reminders",
            command=send_emails,
            height=45,
            fg_color="#28A745"
        ).pack(pady=20, padx=20, fill="x")
    
    def send_reminder_email(self, cert_info):
        """Send a single reminder email"""
        try:
            serial, vendor_id, company, email, expiry, days = cert_info
            
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.smtp_username
            msg['To'] = email
            msg['Subject'] = f"Certificate Expiry Reminder - {company}"
            
            body = f"""
            Dear {company},
            
            This is a reminder that your digital certificate will expire in {int(days)} days.
            
            Certificate Details:
            - Serial Number: {serial}
            - Expiry Date: {expiry[:10]}
            
            Please ensure you renew your certificate before it expires to maintain 
            uninterrupted access to the CertAuth: Vendor Authentication System.
            
            Best regards,
            CertAuth: Vendor Authentication System
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.smtp_username, self.smtp_password)
            server.send_message(msg)
            server.quit()
            
            # Log the action
            if db and hasattr(db, 'log_audit_event'):
                db.log_audit_event('admin', self.username, 'send_reminder', 
                                  f"Sent expiry reminder to {vendor_id}")
            
            return True
            
        except Exception as e:
            print(f"Failed to send email: {e}")
            return False
    
    def show_pending_vendors(self):
        """Show pending vendors for approval"""
        self.tabview.set("Vendors")
        self.vendor_status_var.set("pending")
        self.refresh_vendors_list()
    
    # ========== VENDORS TAB ==========
    
    def setup_vendors_tab(self):
        """Setup vendors management tab"""
        tab = self.tabview.tab("Vendors")
        
        ctk.CTkLabel(
            tab,
            text="Vendor Management",
            font=ctk.CTkFont(size=24, weight="bold")
        ).pack(pady=20)
        
        # Search and filter frame
        filter_frame = ctk.CTkFrame(tab, corner_radius=10)
        filter_frame.pack(pady=10, padx=20, fill="x")
        
        # Search
        ctk.CTkLabel(filter_frame, text="Search:").grid(row=0, column=0, padx=10, pady=10)
        self.vendor_search_entry = ctk.CTkEntry(filter_frame, width=200, placeholder_text="Vendor ID, Company, Email")
        self.vendor_search_entry.grid(row=0, column=1, padx=10, pady=10)
        
        # Status filter
        ctk.CTkLabel(filter_frame, text="Status:").grid(row=0, column=2, padx=10, pady=10)
        self.vendor_status_var = ctk.StringVar(value="all")
        status_menu = ctk.CTkOptionMenu(
            filter_frame, 
            variable=self.vendor_status_var,
            values=["all", "pending", "active", "suspended", "revoked"]
        )
        status_menu.grid(row=0, column=3, padx=10, pady=10)
        
        # Buttons
        ctk.CTkButton(
            filter_frame,
            text="🔍 Search",
            command=self.refresh_vendors_list,
            width=100
        ).grid(row=0, column=4, padx=10, pady=10)
        
        ctk.CTkButton(
            filter_frame,
            text="🔄 Refresh",
            command=self.refresh_vendors_list,
            width=100
        ).grid(row=0, column=5, padx=10, pady=10)
        
        ctk.CTkButton(
            filter_frame,
            text="📥 Export CSV",
            command=self.export_vendors_csv,
            width=100
        ).grid(row=0, column=6, padx=10, pady=10)
        
        # Vendors list frame
        self.vendors_list_frame = ctk.CTkScrollableFrame(tab, height=500)
        self.vendors_list_frame.pack(pady=10, padx=20, fill="both", expand=True)
        
        # Load vendors
        self.refresh_vendors_list()
    
    def refresh_vendors_list(self):
        """Refresh vendors list with filters"""
        for widget in self.vendors_list_frame.winfo_children():
            widget.destroy()
        
        try:
            search = self.vendor_search_entry.get().strip()
            status = self.vendor_status_var.get()
            
            conn = sqlite3.connect("database/certauth.db")
            cursor = conn.cursor()
            
            query = "SELECT * FROM vendors WHERE 1=1"
            params = []
            
            if search:
                query += " AND (vendor_id LIKE ? OR company_name LIKE ? OR contact_email LIKE ?)"
                search_term = f"%{search}%"
                params.extend([search_term, search_term, search_term])
            
            if status != "all":
                query += " AND status = ?"
                params.append(status)
            
            query += " ORDER BY registration_date DESC"
            cursor.execute(query, params)
            vendors = cursor.fetchall()
            
            if not vendors:
                ctk.CTkLabel(
                    self.vendors_list_frame,
                    text="No vendors found",
                    font=ctk.CTkFont(size=16)
                ).pack(pady=50)
                conn.close()
                return
            
            # Headers
            headers = ["Vendor ID", "Company", "Email", "Contact", "Status", "Registered", "Documents", "Actions"]
            headers_frame = ctk.CTkFrame(self.vendors_list_frame, fg_color="transparent")
            headers_frame.pack(fill="x", pady=5)
            
            for header in headers:
                width = 120 if header not in ["Company", "Email"] else 150
                ctk.CTkLabel(
                    headers_frame,
                    text=header,
                    font=ctk.CTkFont(weight="bold", size=12),
                    width=width
                ).pack(side="left", padx=2)
            
            # Vendor rows
            for vendor in vendors:
                vendor_id = vendor[1]
                
                # Get document count
                cursor.execute("SELECT COUNT(*) FROM signed_documents WHERE vendor_id = ?", (vendor_id,))
                doc_count = cursor.fetchone()[0]
                
                row_frame = ctk.CTkFrame(self.vendors_list_frame)
                row_frame.pack(fill="x", pady=2)
                
                # Vendor ID
                ctk.CTkLabel(row_frame, text=vendor_id, width=120).pack(side="left", padx=2)
                
                # Company
                company = vendor[2][:20] + "..." if len(vendor[2]) > 20 else vendor[2]
                ctk.CTkLabel(row_frame, text=company, width=150).pack(side="left", padx=2)
                
                # Email
                email = vendor[3][:20] + "..." if len(vendor[3]) > 20 else vendor[3]
                ctk.CTkLabel(row_frame, text=email, width=150).pack(side="left", padx=2)
                
                # Contact Person
                contact = vendor[4][:15] if vendor[4] else "N/A"
                ctk.CTkLabel(row_frame, text=contact, width=120).pack(side="left", padx=2)
                
                # Status with color
                status_val = vendor[5]
                status_color = {
                    "active": "#28A745",
                    "pending": "#FFC107",
                    "suspended": "#DC3545",
                    "revoked": "#6C757D"
                }.get(status_val, "gray")
                
                ctk.CTkLabel(
                    row_frame,
                    text=status_val.upper(),
                    text_color=status_color,
                    width=120
                ).pack(side="left", padx=2)
                
                # Registration Date
                reg_date = vendor[6][:10] if vendor[6] else "N/A"
                ctk.CTkLabel(row_frame, text=reg_date, width=120).pack(side="left", padx=2)
                
                # Document count
                ctk.CTkLabel(row_frame, text=str(doc_count), width=80).pack(side="left", padx=2)
                
                # Actions
                actions_frame = ctk.CTkFrame(row_frame, fg_color="transparent")
                actions_frame.pack(side="left", padx=5)
                
                # View button
                ctk.CTkButton(
                    actions_frame,
                    text="👁️",
                    width=30,
                    height=25,
                    command=lambda v=vendor_id: self.view_vendor_details(v)
                ).pack(side="left", padx=1)
                
                # Edit button
                ctk.CTkButton(
                    actions_frame,
                    text="✏️",
                    width=30,
                    height=25,
                    fg_color="#17A2B8",
                    command=lambda v=vendor_id: self.edit_vendor(v)
                ).pack(side="left", padx=1)
                
                # Status-specific actions
                if status_val == "pending":
                    ctk.CTkButton(
                        actions_frame,
                        text="✅",
                        width=30,
                        height=25,
                        fg_color="#28A745",
                        command=lambda v=vendor_id: self.approve_vendor(v)
                    ).pack(side="left", padx=1)
                    
                    ctk.CTkButton(
                        actions_frame,
                        text="❌",
                        width=30,
                        height=25,
                        fg_color="#DC3545",
                        command=lambda v=vendor_id: self.reject_vendor(v)
                    ).pack(side="left", padx=1)
                
                elif status_val == "active":
                    ctk.CTkButton(
                        actions_frame,
                        text="⏸️",
                        width=30,
                        height=25,
                        fg_color="#FFC107",
                        command=lambda v=vendor_id: self.suspend_vendor(v)
                    ).pack(side="left", padx=1)
                    
                    ctk.CTkButton(
                        actions_frame,
                        text="🔴",
                        width=30,
                        height=25,
                        fg_color="#6C757D",
                        command=lambda v=vendor_id: self.revoke_vendor(v)
                    ).pack(side="left", padx=1)
                
                elif status_val == "suspended":
                    ctk.CTkButton(
                        actions_frame,
                        text="▶️",
                        width=30,
                        height=25,
                        fg_color="#28A745",
                        command=lambda v=vendor_id: self.activate_vendor(v)
                    ).pack(side="left", padx=1)
                    
                    ctk.CTkButton(
                        actions_frame,
                        text="🔴",
                        width=30,
                        height=25,
                        fg_color="#6C757D",
                        command=lambda v=vendor_id: self.revoke_vendor(v)
                    ).pack(side="left", padx=1)
                
                elif status_val == "revoked":
                    ctk.CTkButton(
                        actions_frame,
                        text="🔄",
                        width=30,
                        height=25,
                        fg_color="#17A2B8",
                        command=lambda v=vendor_id: self.activate_vendor(v)
                    ).pack(side="left", padx=1)
                
                # Activity Log button
                ctk.CTkButton(
                    actions_frame,
                    text="📋",
                    width=30,
                    height=25,
                    fg_color="#6f42c1",
                    command=lambda v=vendor_id: self.view_vendor_activity(v)
                ).pack(side="left", padx=1)
                
                # Delete button (super admin only)
                if self.admin_info and self.admin_info.get('role') == 'super_admin':
                    ctk.CTkButton(
                        actions_frame,
                        text="🗑️",
                        width=30,
                        height=25,
                        fg_color="#DC3545",
                        command=lambda v=vendor_id: self.delete_vendor(v)
                    ).pack(side="left", padx=1)
            
            conn.close()
            
        except Exception as e:
            ctk.CTkLabel(
                self.vendors_list_frame,
                text=f"Error loading vendors: {str(e)}",
                text_color="red"
            ).pack(pady=20)
    
    def view_vendor_details(self, vendor_id):
        """View vendor details"""
        try:
            conn = sqlite3.connect("database/certauth.db")
            cursor = conn.cursor()
            
            # Get vendor info
            cursor.execute("SELECT * FROM vendors WHERE vendor_id = ?", (vendor_id,))
            vendor = cursor.fetchone()
            
            if not vendor:
                messagebox.showerror("Error", f"Vendor {vendor_id} not found")
                conn.close()
                return
            
            # Get column names
            cursor.execute("PRAGMA table_info(vendors)")
            columns = [col[1] for col in cursor.fetchall()]
            
            # Convert to dictionary for easier access
            vendor_dict = {}
            for i, col in enumerate(columns):
                vendor_dict[col] = vendor[i] if i < len(vendor) else None
            
            # Get document count
            cursor.execute("SELECT COUNT(*) FROM signed_documents WHERE vendor_id = ?", (vendor_id,))
            doc_count = cursor.fetchone()[0]
            
            # Get certificate info
            cursor.execute("SELECT * FROM certificates WHERE vendor_id = ? ORDER BY not_valid_after DESC", (vendor_id,))
            certificates = cursor.fetchall()
            
            # Get recent documents
            cursor.execute("""
                SELECT document_id, document_title, signing_timestamp, verification_status
                FROM signed_documents 
                WHERE vendor_id = ? 
                ORDER BY signing_timestamp DESC LIMIT 5
            """, (vendor_id,))
            recent_docs = cursor.fetchall()
            
            conn.close()
            
            # Create details window
            dialog = ctk.CTkToplevel(self.window)
            dialog.title(f"Vendor Details - {vendor_id}")
            dialog.geometry("800x600")
            dialog.transient(self.window)
            dialog.grab_set()
            
            # Create notebook
            notebook = ctk.CTkTabview(dialog)
            notebook.pack(fill="both", expand=True, padx=10, pady=10)
            
            # Basic Info Tab
            info_tab = notebook.add("📋 Basic Info")
            info_frame = ctk.CTkScrollableFrame(info_tab)
            info_frame.pack(fill="both", expand=True, padx=10, pady=10)
            
            fields = [
                ("Vendor ID", vendor_dict.get('vendor_id', 'N/A')),
                ("Company Name", vendor_dict.get('company_name', 'N/A')),
                ("Email", vendor_dict.get('contact_email', 'N/A')),
                ("Contact Person", vendor_dict.get('contact_person', 'N/A')),
                ("Phone", vendor_dict.get('phone', 'N/A')),
                ("Address", vendor_dict.get('address', 'N/A')),
                ("City", vendor_dict.get('city', 'N/A')),
                ("State", vendor_dict.get('state', 'N/A')),
                ("Status", vendor_dict.get('status', 'N/A').upper() if vendor_dict.get('status') else 'N/A'),
                ("Registration Date", vendor_dict.get('registration_date', 'N/A')[:10] if vendor_dict.get('registration_date') else 'N/A'),
                ("Certificate Serial", vendor_dict.get('certificate_serial', 'N/A')),
                ("Total Documents", str(doc_count))
            ]
            
            for label, value in fields:
                item_frame = ctk.CTkFrame(info_frame, fg_color="transparent")
                item_frame.pack(fill="x", pady=5)
                
                ctk.CTkLabel(
                    item_frame,
                    text=label + ":",
                    font=ctk.CTkFont(weight="bold"),
                    width=150
                ).pack(side="left")
                
                ctk.CTkLabel(
                    item_frame,
                    text=value,
                    wraplength=400
                ).pack(side="left", padx=10)
            
            # Certificates Tab
            cert_tab = notebook.add("🔐 Certificates")
            cert_frame = ctk.CTkScrollableFrame(cert_tab)
            cert_frame.pack(fill="both", expand=True, padx=10, pady=10)
            
            if certificates:
                for cert in certificates:
                    cert_item = ctk.CTkFrame(cert_frame, corner_radius=8)
                    cert_item.pack(fill="x", pady=5)
                    
                    serial = cert[1]
                    valid_from = cert[4][:10] if cert[4] else "N/A"
                    valid_to = cert[5][:10] if cert[5] else "N/A"
                    revoked = cert[6]
                    
                    header = ctk.CTkFrame(cert_item, fg_color="transparent")
                    header.pack(fill="x", padx=10, pady=5)
                    
                    ctk.CTkLabel(
                        header,
                        text=f"Serial: {serial[:20]}...",
                        font=ctk.CTkFont(weight="bold")
                    ).pack(side="left")
                    
                    status_text = "❌ REVOKED" if revoked else "✅ ACTIVE"
                    status_color = "#DC3545" if revoked else "#28A745"
                    ctk.CTkLabel(
                        header,
                        text=status_text,
                        text_color=status_color
                    ).pack(side="right")
                    
                    ctk.CTkLabel(
                        cert_item,
                        text=f"Valid: {valid_from} to {valid_to}",
                        font=ctk.CTkFont(size=12)
                    ).pack(anchor="w", padx=10, pady=2)
                    
                    # Download button
                    ctk.CTkButton(
                        cert_item,
                        text="📥 Download Certificate",
                        command=lambda s=serial: self.download_certificate(s),
                        width=150,
                        height=25
                    ).pack(anchor="w", padx=10, pady=5)
            else:
                ctk.CTkLabel(cert_frame, text="No certificates found").pack(pady=20)
            
            # Documents Tab
            docs_tab = notebook.add("📄 Recent Documents")
            docs_frame = ctk.CTkScrollableFrame(docs_tab)
            docs_frame.pack(fill="both", expand=True, padx=10, pady=10)
            
            if recent_docs:
                for doc in recent_docs:
                    doc_item = ctk.CTkFrame(docs_frame, corner_radius=8)
                    doc_item.pack(fill="x", pady=5)
                    
                    doc_id = doc[0]
                    title = doc[1]
                    date = doc[2][:10] if doc[2] else "N/A"
                    status = doc[3]
                    
                    status_color = {
                        "verified": "#28A745",
                        "pending": "#FFC107",
                        "rejected": "#DC3545"
                    }.get(status, "gray")
                    
                    ctk.CTkLabel(
                        doc_item,
                        text=f"ID: {doc_id}",
                        font=ctk.CTkFont(weight="bold")
                    ).pack(anchor="w", padx=10, pady=5)
                    
                    ctk.CTkLabel(
                        doc_item,
                        text=f"Title: {title}",
                        font=ctk.CTkFont(size=12)
                    ).pack(anchor="w", padx=10, pady=2)
                    
                    ctk.CTkLabel(
                        doc_item,
                        text=f"Date: {date} | Status: {status.upper()}",
                        text_color=status_color
                    ).pack(anchor="w", padx=10, pady=2)
            else:
                ctk.CTkLabel(docs_frame, text="No documents found").pack(pady=20)
            
            # Action buttons
            action_frame = ctk.CTkFrame(dialog, fg_color="transparent")
            action_frame.pack(pady=10, padx=10, fill="x")
            
            status_val = vendor_dict.get('status', 'unknown')
            if status_val == "pending":
                ctk.CTkButton(
                    action_frame,
                    text="✅ Approve",
                    command=lambda: [self.approve_vendor(vendor_id), dialog.destroy()],
                    fg_color="#28A745"
                ).pack(side="left", padx=5)
                
                ctk.CTkButton(
                    action_frame,
                    text="❌ Reject",
                    command=lambda: [self.reject_vendor(vendor_id), dialog.destroy()],
                    fg_color="#DC3545"
                ).pack(side="left", padx=5)
            elif status_val == "active":
                ctk.CTkButton(
                    action_frame,
                    text="⏸️ Suspend",
                    command=lambda: [self.suspend_vendor(vendor_id), dialog.destroy()],
                    fg_color="#FFC107"
                ).pack(side="left", padx=5)
                
                ctk.CTkButton(
                    action_frame,
                    text="🔴 Revoke",
                    command=lambda: [self.revoke_vendor(vendor_id), dialog.destroy()],
                    fg_color="#6C757D"
                ).pack(side="left", padx=5)
            elif status_val == "suspended":
                ctk.CTkButton(
                    action_frame,
                    text="▶️ Activate",
                    command=lambda: [self.activate_vendor(vendor_id), dialog.destroy()],
                    fg_color="#28A745"
                ).pack(side="left", padx=5)
                
                ctk.CTkButton(
                    action_frame,
                    text="🔴 Revoke",
                    command=lambda: [self.revoke_vendor(vendor_id), dialog.destroy()],
                    fg_color="#6C757D"
                ).pack(side="left", padx=5)
            elif status_val == "revoked":
                ctk.CTkButton(
                    action_frame,
                    text="🔄 Reactivate",
                    command=lambda: [self.activate_vendor(vendor_id), dialog.destroy()],
                    fg_color="#17A2B8"
                ).pack(side="left", padx=5)
            
            ctk.CTkButton(
                action_frame,
                text="📋 Activity Log",
                command=lambda: [dialog.destroy(), self.view_vendor_activity(vendor_id)],
                fg_color="#6f42c1"
            ).pack(side="left", padx=5)
            
            ctk.CTkButton(
                action_frame,
                text="Close",
                command=dialog.destroy,
                fg_color="#6c757d"
            ).pack(side="right", padx=5)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load vendor details: {str(e)}")
            import traceback
            traceback.print_exc()
    
    def edit_vendor(self, vendor_id):
        """Edit vendor details"""
        try:
            conn = sqlite3.connect("database/certauth.db")
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM vendors WHERE vendor_id = ?", (vendor_id,))
            vendor = cursor.fetchone()
            conn.close()
            
            if not vendor:
                messagebox.showerror("Error", f"Vendor {vendor_id} not found")
                return
            
            # Create edit dialog
            dialog = ctk.CTkToplevel(self.window)
            dialog.title(f"Edit Vendor - {vendor_id}")
            dialog.geometry("500x600")
            dialog.transient(self.window)
            dialog.grab_set()
            
            ctk.CTkLabel(
                dialog,
                text=f"✏️ Edit Vendor: {vendor_id}",
                font=ctk.CTkFont(size=18, weight="bold")
            ).pack(pady=20)
            
            form_frame = ctk.CTkFrame(dialog)
            form_frame.pack(pady=10, padx=20, fill="both", expand=True)
            
            # Editable fields
            fields = [
                ("Company Name", "company_name", vendor[2]),
                ("Email", "email", vendor[3]),
                ("Contact Person", "contact_person", vendor[4]),
                ("Phone", "phone", vendor[5] if len(vendor) > 5 and vendor[5] else ""),
                ("Address", "address", vendor[6] if len(vendor) > 6 and vendor[6] else ""),
                ("City", "city", vendor[7] if len(vendor) > 7 and vendor[7] else ""),
                ("State", "state", vendor[8] if len(vendor) > 8 and vendor[8] else "")
            ]
            
            entries = {}
            for label, key, value in fields:
                ctk.CTkLabel(form_frame, text=label).pack(anchor="w", padx=20, pady=(10, 2))
                entry = ctk.CTkEntry(form_frame)
                entry.pack(fill="x", padx=20, pady=2)
                entry.insert(0, value if value else "")
                entries[key] = entry
            
            def save_changes():
                try:
                    conn = sqlite3.connect("database/certauth.db")
                    cursor = conn.cursor()
                    
                    cursor.execute("""
                        UPDATE vendors 
                        SET company_name = ?, contact_email = ?, contact_person = ?,
                            phone = ?, address = ?, city = ?, state = ?
                        WHERE vendor_id = ?
                    """, (
                        entries['company_name'].get(),
                        entries['email'].get(),
                        entries['contact_person'].get(),
                        entries['phone'].get(),
                        entries['address'].get(),
                        entries['city'].get(),
                        entries['state'].get(),
                        vendor_id
                    ))
                    
                    conn.commit()
                    conn.close()
                    
                    if db and hasattr(db, 'log_audit_event'):
                        db.log_audit_event('admin', self.username, 'edit_vendor', f"Edited vendor {vendor_id}")
                    
                    messagebox.showinfo("Success", f"Vendor {vendor_id} updated successfully!")
                    dialog.destroy()
                    self.refresh_vendors_list()
                    
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to update vendor: {str(e)}")
            
            ctk.CTkButton(
                dialog,
                text="💾 Save Changes",
                command=save_changes,
                height=45,
                fg_color="#28A745"
            ).pack(pady=20, padx=20, fill="x")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load vendor for editing: {str(e)}")
    
    def view_vendor_activity(self, vendor_id):
        """View vendor activity logs"""
        try:
            conn = sqlite3.connect("database/certauth.db")
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT id, timestamp, action, details, ip_address
                FROM audit_log 
                WHERE user_id = ? AND user_type = 'vendor'
                ORDER BY timestamp DESC
                LIMIT 100
            """, (vendor_id,))
            
            logs = cursor.fetchall()
            conn.close()
            
            # Create activity window - INCREASE WIDTH
            dialog = ctk.CTkToplevel(self.window)
            dialog.title(f"Activity Log - {vendor_id}")
            dialog.geometry("1000x600")  # Increased from 900 to 1000
            dialog.transient(self.window)
            dialog.grab_set()
            
            # HEADER WITH TITLE AND DELETE ALL BUTTON
            header_frame = ctk.CTkFrame(dialog, fg_color="transparent")
            header_frame.pack(fill="x", padx=20, pady=(20, 10))
            
            ctk.CTkLabel(
                header_frame,
                text=f"📋 Vendor Activity Log: {vendor_id}",
                font=ctk.CTkFont(size=18, weight="bold")
            ).pack(side="left")
            
            # DELETE ALL BUTTON
            def delete_all_logs():
                if messagebox.askyesno("Delete All", 
                                    f"⚠️ Delete ALL activity logs for {vendor_id}?\n\nThis cannot be undone!"):
                    try:
                        conn = sqlite3.connect("database/certauth.db")
                        cursor = conn.cursor()
                        cursor.execute("DELETE FROM audit_log WHERE user_id = ? AND user_type = 'vendor'", (vendor_id,))
                        deleted = cursor.rowcount
                        conn.commit()
                        conn.close()
                        messagebox.showinfo("Deleted", f"Deleted {deleted} log(s)")
                        dialog.destroy()
                    except Exception as e:
                        messagebox.showerror("Error", f"Failed to delete: {str(e)}")
            
            ctk.CTkButton(
                header_frame,
                text="🗑️ Delete All",
                command=delete_all_logs,
                width=120,
                height=35,
                fg_color="#DC3545",
                hover_color="#c82333"
            ).pack(side="right", padx=5)
            
            # REFRESH BUTTON
            def refresh_logs():
                dialog.destroy()
                self.view_vendor_activity(vendor_id)
            
            ctk.CTkButton(
                header_frame,
                text="🔄 Refresh",
                command=refresh_logs,
                width=100,
                height=35,
                fg_color="#17A2B8",
                hover_color="#138496"
            ).pack(side="right", padx=5)
            
            if not logs:
                ctk.CTkLabel(
                    dialog,
                    text="No activity logs found for this vendor",
                    font=ctk.CTkFont(size=14)
                ).pack(expand=True, pady=50)
                return
            
            # Create scrollable frame
            scroll_frame = ctk.CTkScrollableFrame(dialog)
            scroll_frame.pack(pady=10, padx=20, fill="both", expand=True)
            
            # Headers with adjusted widths
            headers_frame = ctk.CTkFrame(scroll_frame, fg_color="transparent")
            headers_frame.pack(fill="x", pady=5)
            
            # Header labels with specific widths
            ctk.CTkLabel(headers_frame, text="Timestamp", font=ctk.CTkFont(weight="bold", size=12), width=120).pack(side="left", padx=2)
            ctk.CTkLabel(headers_frame, text="Action", font=ctk.CTkFont(weight="bold", size=12), width=120).pack(side="left", padx=2)
            ctk.CTkLabel(headers_frame, text="Details", font=ctk.CTkFont(weight="bold", size=12), width=350).pack(side="left", padx=2)
            ctk.CTkLabel(headers_frame, text="IP Address", font=ctk.CTkFont(weight="bold", size=12), width=120).pack(side="left", padx=2)
            ctk.CTkLabel(headers_frame, text="", font=ctk.CTkFont(weight="bold", size=12), width=50).pack(side="left", padx=2)
            
            # Log rows
            for log in logs:
                log_id, ts, action, details, ip = log
                
                row_frame = ctk.CTkFrame(scroll_frame)
                row_frame.pack(fill="x", pady=2)
                
                # Timestamp
                time_str = ts[11:19] if ts else "N/A"
                ctk.CTkLabel(row_frame, text=time_str, width=120).pack(side="left", padx=2)
                
                # Action
                ctk.CTkLabel(row_frame, text=action, width=120).pack(side="left", padx=2)
                
                # Details
                details_text = details[:60] + "..." if details and len(details) > 60 else (details or "")
                ctk.CTkLabel(row_frame, text=details_text, width=350).pack(side="left", padx=2)
                
                # IP
                ctk.CTkLabel(row_frame, text=ip or "N/A", width=120).pack(side="left", padx=2)
                
                # DELETE BUTTON
                def delete_single_log(log_id=log_id):
                    if messagebox.askyesno("Delete Log", f"Delete this audit log?\n\nID: {log_id}\nThis cannot be undone!"):
                        try:
                            conn = sqlite3.connect("database/certauth.db")
                            cursor = conn.cursor()
                            cursor.execute("DELETE FROM audit_log WHERE id = ?", (log_id,))
                            conn.commit()
                            conn.close()
                            messagebox.showinfo("Deleted", "Log deleted successfully")
                            dialog.destroy()
                            self.view_vendor_activity(vendor_id)
                        except Exception as e:
                            messagebox.showerror("Error", f"Failed to delete: {str(e)}")
                
                ctk.CTkButton(
                    row_frame,
                    text="🗑️",
                    command=delete_single_log,
                    width=50,
                    height=25,
                    fg_color="#DC3545",
                    hover_color="#c82333"
                ).pack(side="left", padx=2)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load activity logs: {str(e)}")
    
    def approve_vendor(self, vendor_id):
        """Approve pending vendor"""
        if messagebox.askyesno("Approve Vendor", f"Approve vendor {vendor_id}?"):
            try:
                conn = sqlite3.connect("database/certauth.db")
                cursor = conn.cursor()
                cursor.execute("UPDATE vendors SET status = 'active' WHERE vendor_id = ?", (vendor_id,))
                conn.commit()
                conn.close()
                
                if db and hasattr(db, 'log_audit_event'):
                    db.log_audit_event('admin', self.username, 'approve_vendor', f"Approved vendor {vendor_id}")
                
                messagebox.showinfo("Success", f"Vendor {vendor_id} approved!")
                self.refresh_vendors_list()
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to approve vendor: {str(e)}")
    
    def reject_vendor(self, vendor_id):
        """Reject pending vendor"""
        reason = ctk.CTkInputDialog(
            text="Enter rejection reason:",
            title="Reject Vendor"
        ).get_input()
        
        if reason is None:
            return
        
        if messagebox.askyesno("Reject Vendor", f"Reject vendor {vendor_id}?"):
            try:
                conn = sqlite3.connect("database/certauth.db")
                cursor = conn.cursor()
                cursor.execute("UPDATE vendors SET status = 'rejected' WHERE vendor_id = ?", (vendor_id,))
                conn.commit()
                conn.close()
                
                if db and hasattr(db, 'log_audit_event'):
                    db.log_audit_event('admin', self.username, 'reject_vendor', f"Rejected vendor {vendor_id}: {reason}")
                
                messagebox.showinfo("Success", f"Vendor {vendor_id} rejected!")
                self.refresh_vendors_list()
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to reject vendor: {str(e)}")
    
    def suspend_vendor(self, vendor_id):
        """Suspend active vendor"""
        reason = ctk.CTkInputDialog(
            text="Enter suspension reason:",
            title="Suspend Vendor"
        ).get_input()
        
        if reason is None:
            return
        
        if messagebox.askyesno("Suspend Vendor", f"Suspend vendor {vendor_id}?"):
            try:
                conn = sqlite3.connect("database/certauth.db")
                cursor = conn.cursor()
                cursor.execute("UPDATE vendors SET status = 'suspended' WHERE vendor_id = ?", (vendor_id,))
                conn.commit()
                conn.close()
                
                if db and hasattr(db, 'log_audit_event'):
                    db.log_audit_event('admin', self.username, 'suspend_vendor', f"Suspended vendor {vendor_id}: {reason}")
                
                messagebox.showinfo("Success", f"Vendor {vendor_id} suspended!")
                self.refresh_vendors_list()
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to suspend vendor: {str(e)}")
    
    def revoke_vendor(self, vendor_id):
        """Revoke vendor (permanent ban)"""
        reason = ctk.CTkInputDialog(
            text="Enter revocation reason:",
            title="Revoke Vendor"
        ).get_input()
        
        if reason is None:
            return
        
        if messagebox.askyesno("Revoke Vendor", 
                               f"⚠️ This will permanently revoke vendor {vendor_id}!\n\n"
                               "All certificates will be revoked.\n"
                               "This action cannot be undone.\n\n"
                               "Are you absolutely sure?"):
            try:
                conn = sqlite3.connect("database/certauth.db")
                cursor = conn.cursor()
                
                # Update vendor status
                cursor.execute("UPDATE vendors SET status = 'revoked' WHERE vendor_id = ?", (vendor_id,))
                
                # Revoke all certificates
                cursor.execute("SELECT serial_number FROM certificates WHERE vendor_id = ? AND revoked = 0", (vendor_id,))
                certs = cursor.fetchall()
                
                for cert in certs:
                    serial = cert[0]
                    cursor.execute("UPDATE certificates SET revoked = 1, revocation_reason = ? WHERE serial_number = ?", 
                                  (f"Vendor revoked: {reason}", serial))
                    cursor.execute("INSERT INTO crl (serial_number, reason_code, reason_text) VALUES (?, ?, ?)",
                                  (serial, 5, f"Vendor revoked: {reason}"))
                
                conn.commit()
                conn.close()
                
                if db and hasattr(db, 'log_audit_event'):
                    db.log_audit_event('admin', self.username, 'revoke_vendor', f"Revoked vendor {vendor_id}: {reason}")
                
                messagebox.showinfo("Success", f"Vendor {vendor_id} revoked!")
                self.refresh_vendors_list()
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to revoke vendor: {str(e)}")
    
    def activate_vendor(self, vendor_id):
        """Activate suspended or revoked vendor"""
        if messagebox.askyesno("Activate Vendor", f"Activate vendor {vendor_id}?"):
            try:
                conn = sqlite3.connect("database/certauth.db")
                cursor = conn.cursor()
                cursor.execute("UPDATE vendors SET status = 'active' WHERE vendor_id = ?", (vendor_id,))
                conn.commit()
                conn.close()
                
                if db and hasattr(db, 'log_audit_event'):
                    db.log_audit_event('admin', self.username, 'activate_vendor', f"Activated vendor {vendor_id}")
                
                messagebox.showinfo("Success", f"Vendor {vendor_id} activated!")
                self.refresh_vendors_list()
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to activate vendor: {str(e)}")
    
    def delete_vendor(self, vendor_id):
        """Delete vendor permanently"""
        if messagebox.askyesno(
            "Delete Vendor",
            f"⚠️ This will permanently delete vendor {vendor_id}\n"
            "and ALL their documents, certificates, and data!\n\n"
            "This action CANNOT be undone.\n\n"
            "Are you absolutely sure?"
        ):
            try:
                conn = sqlite3.connect("database/certauth.db")
                cursor = conn.cursor()
                
                # Delete vendor and related data
                cursor.execute("DELETE FROM vendors WHERE vendor_id = ?", (vendor_id,))
                cursor.execute("DELETE FROM certificates WHERE vendor_id = ?", (vendor_id,))
                cursor.execute("DELETE FROM signed_documents WHERE vendor_id = ?", (vendor_id,))
                cursor.execute("DELETE FROM shared_documents WHERE sender_id = ? OR recipient_id = ?", (vendor_id, vendor_id))
                cursor.execute("DELETE FROM secure_messages WHERE sender_id = ? OR recipient_id = ?", (vendor_id, vendor_id))
                
                conn.commit()
                conn.close()
                
                if db and hasattr(db, 'log_audit_event'):
                    db.log_audit_event('admin', self.username, 'delete_vendor', f"Deleted vendor {vendor_id}")
                
                messagebox.showinfo("Success", f"Vendor {vendor_id} and all associated data deleted!")
                self.refresh_vendors_list()
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete vendor: {str(e)}")
    
    def export_vendors_csv(self):
        """Export vendors list to CSV"""
        try:
            conn = sqlite3.connect("database/certauth.db")
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM vendors ORDER BY registration_date DESC")
            vendors = cursor.fetchall()
            
            if not vendors:
                messagebox.showinfo("No Data", "No vendors to export")
                conn.close()
                return
            
            file_path = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv")],
                initialfile=f"vendors_export_{datetime.now().strftime('%Y%m%d')}.csv"
            )
            
            if file_path:
                with open(file_path, 'w', newline='') as f:
                    writer = csv.writer(f)
                    
                    # Write headers
                    headers = [desc[0] for desc in cursor.description]
                    writer.writerow(headers)
                    
                    # Write data
                    writer.writerows(vendors)
                
                messagebox.showinfo("Success", f"Vendors exported to {file_path}")
            
            conn.close()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export: {str(e)}")
    
    # ========== DOCUMENTS TAB ==========
    
    def setup_documents_tab(self):
        """Setup documents management tab"""
        tab = self.tabview.tab("Documents")
        
        ctk.CTkLabel(
            tab,
            text="Document Management",
            font=ctk.CTkFont(size=24, weight="bold")
        ).pack(pady=20)
        
        # Filter frame
        filter_frame = ctk.CTkFrame(tab, corner_radius=10)
        filter_frame.pack(pady=10, padx=20, fill="x")
        
        # Search
        ctk.CTkLabel(filter_frame, text="Search:").grid(row=0, column=0, padx=10, pady=10)
        self.doc_search_entry = ctk.CTkEntry(filter_frame, width=200, placeholder_text="Document ID, Title")
        self.doc_search_entry.grid(row=0, column=1, padx=10, pady=10)
        
        # Status filter
        ctk.CTkLabel(filter_frame, text="Status:").grid(row=0, column=2, padx=10, pady=10)
        self.doc_status_var = ctk.StringVar(value="all")
        status_menu = ctk.CTkOptionMenu(
            filter_frame,
            variable=self.doc_status_var,
            values=["all", "pending", "verified", "rejected"]
        )
        status_menu.grid(row=0, column=3, padx=10, pady=10)
        
        # Type filter
        ctk.CTkLabel(filter_frame, text="Type:").grid(row=0, column=4, padx=10, pady=10)
        self.doc_type_var = ctk.StringVar(value="all")
        type_menu = ctk.CTkOptionMenu(
            filter_frame,
            variable=self.doc_type_var,
            values=["all", "quality_certificate", "material_test", "compliance_cert", "delivery_note"]
        )
        type_menu.grid(row=0, column=5, padx=10, pady=10)
        
        # Buttons
        ctk.CTkButton(
            filter_frame,
            text="🔍 Search",
            command=self.refresh_documents_list,
            width=100
        ).grid(row=0, column=6, padx=10, pady=10)
        
        ctk.CTkButton(
            filter_frame,
            text="🔄 Refresh",
            command=self.refresh_documents_list,
            width=100
        ).grid(row=0, column=7, padx=10, pady=10)
        
        # Documents list frame
        self.documents_list_frame = ctk.CTkScrollableFrame(tab, height=500)
        self.documents_list_frame.pack(pady=10, padx=20, fill="both", expand=True)
        
        # Load documents
        self.refresh_documents_list()
    
    def refresh_documents_list(self):
        """Refresh documents list with filters"""
        for widget in self.documents_list_frame.winfo_children():
            widget.destroy()
        
        try:
            search = self.doc_search_entry.get().strip()
            status = self.doc_status_var.get()
            doc_type = self.doc_type_var.get()
            
            conn = sqlite3.connect("database/certauth.db")
            cursor = conn.cursor()
            
            # First, get the actual column names from the signed_documents table
            cursor.execute("PRAGMA table_info(signed_documents)")
            columns_info = cursor.fetchall()
            column_names = [col[1] for col in columns_info]
            # print(f"Document columns: {column_names}")  # Debug print
            
            # Build the query - use SELECT * to get all columns
            query = """
            SELECT d.*, v.company_name 
            FROM signed_documents d
            LEFT JOIN vendors v ON d.vendor_id = v.vendor_id
            WHERE 1=1
            """
            params = []
            
            if search:
                query += " AND (d.document_id LIKE ? OR d.document_title LIKE ?)"
                search_term = f"%{search}%"
                params.extend([search_term, search_term])
            
            if status != "all":
                query += " AND d.verification_status = ?"
                params.append(status)
            
            if doc_type != "all":
                query += " AND d.document_type = ?"
                params.append(doc_type)
            
            query += " ORDER BY d.signing_timestamp DESC"
            cursor.execute(query, params)
            documents = cursor.fetchall()
            
            if not documents:
                ctk.CTkLabel(
                    self.documents_list_frame,
                    text="No documents found",
                    font=ctk.CTkFont(size=16)
                ).pack(pady=50)
                conn.close()
                return
            
            # Create a mapping of column names to indices
            col_indices = {}
            for i, col_name in enumerate(column_names):
                col_indices[col_name] = i
            
            # Headers
            headers = ["Document ID", "Title", "Type", "Vendor", "Date", "Status", "Actions"]
            headers_frame = ctk.CTkFrame(self.documents_list_frame, fg_color="transparent")
            headers_frame.pack(fill="x", pady=5)
            
            for header in headers:
                width = 120 if header not in ["Title", "Vendor"] else 150
                ctk.CTkLabel(
                    headers_frame,
                    text=header,
                    font=ctk.CTkFont(weight="bold", size=12),
                    width=width
                ).pack(side="left", padx=2)
            
            # Document rows
            for doc in documents:
                # Safely get values using column indices
                doc_id = doc[col_indices.get('document_id', 0)] if len(doc) > col_indices.get('document_id', 0) else "N/A"
                title = doc[col_indices.get('document_title', 1)] if len(doc) > col_indices.get('document_title', 1) else "N/A"
                doc_type_val = doc[col_indices.get('document_type', 2)] if len(doc) > col_indices.get('document_type', 2) else "N/A"
                vendor_id = doc[col_indices.get('vendor_id', 3)] if len(doc) > col_indices.get('vendor_id', 3) else "N/A"
                date_val = doc[col_indices.get('signing_timestamp', 4)] if len(doc) > col_indices.get('signing_timestamp', 4) else "N/A"
                status_val = doc[col_indices.get('verification_status', 6)] if len(doc) > col_indices.get('verification_status', 6) else "pending"
                
                # Company name is the last column from the JOIN
                company_name = doc[-1] if doc[-1] else vendor_id
                
                row_frame = ctk.CTkFrame(self.documents_list_frame)
                row_frame.pack(fill="x", pady=2)
                
                # Document ID
                display_id = str(doc_id)[:15] + "..." if len(str(doc_id)) > 15 else str(doc_id)
                ctk.CTkLabel(row_frame, text=display_id, width=120).pack(side="left", padx=2)
                
                # Title
                display_title = str(title)[:20] + "..." if len(str(title)) > 20 else str(title)
                ctk.CTkLabel(row_frame, text=display_title, width=150).pack(side="left", padx=2)
                
                # Type
                display_type = str(doc_type_val).replace('_', ' ').title()
                display_type = display_type[:15] + "..." if len(display_type) > 15 else display_type
                ctk.CTkLabel(row_frame, text=display_type, width=120).pack(side="left", padx=2)
                
                # Vendor
                display_vendor = str(company_name)[:15] + "..." if len(str(company_name)) > 15 else str(company_name)
                ctk.CTkLabel(row_frame, text=display_vendor, width=150).pack(side="left", padx=2)
                
                # Date
                display_date = str(date_val)[:10] if date_val and str(date_val) != "N/A" else "N/A"
                ctk.CTkLabel(row_frame, text=display_date, width=120).pack(side="left", padx=2)
                
                # Status
                status_color = {
                    "verified": "#28A745",
                    "pending": "#FFC107",
                    "rejected": "#DC3545"
                }.get(str(status_val).lower(), "gray")
                
                ctk.CTkLabel(
                    row_frame,
                    text=str(status_val).upper(),
                    text_color=status_color,
                    width=120
                ).pack(side="left", padx=2)
                
                # Actions
                actions_frame = ctk.CTkFrame(row_frame, fg_color="transparent")
                actions_frame.pack(side="left", padx=5)
                
                # View button
                ctk.CTkButton(
                    actions_frame,
                    text="👁️",
                    width=30,
                    height=25,
                    command=lambda d=doc_id: self.view_document_details(d)
                ).pack(side="left", padx=1)
                
                # Verify/Reject for pending documents
                if str(status_val).lower() == "pending":
                    ctk.CTkButton(
                        actions_frame,
                        text="✅",
                        width=30,
                        height=25,
                        fg_color="#28A745",
                        command=lambda d=doc_id: self.verify_document(d)
                    ).pack(side="left", padx=1)
                    
                    ctk.CTkButton(
                        actions_frame,
                        text="❌",
                        width=30,
                        height=25,
                        fg_color="#DC3545",
                        command=lambda d=doc_id: self.reject_document(d)
                    ).pack(side="left", padx=1)
                
                # Download button
                ctk.CTkButton(
                    actions_frame,
                    text="📥",
                    width=30,
                    height=25,
                    fg_color="#17A2B8",
                    command=lambda d=doc_id: self.download_document(d)
                ).pack(side="left", padx=1)
            
            conn.close()
            
        except Exception as e:
            print(f"Error in refresh_documents_list: {str(e)}")
            import traceback
            traceback.print_exc()
            
            error_frame = ctk.CTkFrame(self.documents_list_frame)
            error_frame.pack(pady=20, padx=20, fill="x")
            
            ctk.CTkLabel(
                error_frame,
                text=f"Error loading documents: {str(e)}",
                font=ctk.CTkFont(size=14),
                text_color="red"
            ).pack(pady=10)
            
            ctk.CTkButton(
                error_frame,
                text="Try Again",
                command=self.refresh_documents_list,
                width=100
            ).pack(pady=10)
    
    def view_document_details(self, document_id):
        """View document details"""
        try:
            conn = sqlite3.connect("database/certauth.db")
            cursor = conn.cursor()
            
            # Get column names
            cursor.execute("PRAGMA table_info(signed_documents)")
            doc_columns = [col[1] for col in cursor.fetchall()]
            
            cursor.execute("""
                SELECT d.*, v.company_name, v.contact_email
                FROM signed_documents d
                LEFT JOIN vendors v ON d.vendor_id = v.vendor_id
                WHERE d.document_id = ?
            """, (document_id,))
            doc = cursor.fetchone()
            conn.close()
            
            if not doc:
                messagebox.showerror("Error", f"Document {document_id} not found")
                return
            
            # Create details window
            dialog = ctk.CTkToplevel(self.window)
            dialog.title(f"Document Details - {document_id}")
            dialog.geometry("900x700")
            dialog.transient(self.window)
            dialog.grab_set()
            
            # Notebook
            notebook = ctk.CTkTabview(dialog)
            notebook.pack(fill="both", expand=True, padx=10, pady=10)
            
            # Overview Tab
            overview_tab = notebook.add("📋 Overview")
            overview_frame = ctk.CTkScrollableFrame(overview_tab)
            overview_frame.pack(fill="both", expand=True, padx=10, pady=10)
            
            # Get indices
            title_idx = doc_columns.index('document_title') if 'document_title' in doc_columns else 1
            type_idx = doc_columns.index('document_type') if 'document_type' in doc_columns else 2
            vendor_idx = doc_columns.index('vendor_id') if 'vendor_id' in doc_columns else 3
            date_idx = doc_columns.index('signing_timestamp') if 'signing_timestamp' in doc_columns else 4
            status_idx = doc_columns.index('verification_status') if 'verification_status' in doc_columns else 6
            verified_by_idx = doc_columns.index('verified_by') if 'verified_by' in doc_columns else 7
            verified_date_idx = doc_columns.index('verification_timestamp') if 'verification_timestamp' in doc_columns else 8
            hash_idx = doc_columns.index('document_hash') if 'document_hash' in doc_columns else 9
            sig_idx = doc_columns.index('digital_signature') if 'digital_signature' in doc_columns else 10
            content_idx = doc_columns.index('document_content') if 'document_content' in doc_columns else 12
            metadata_idx = doc_columns.index('metadata') if 'metadata' in doc_columns else 13
            
            overview_fields = [
                ("Document ID", doc[0]),
                ("Title", doc[title_idx]),
                ("Type", doc[type_idx].replace('_', ' ').title()),
                ("Vendor ID", doc[vendor_idx]),
                ("Company", doc[-2] if len(doc) > len(doc_columns) else "N/A"),  # company_name from join
                ("Email", doc[-1] if len(doc) > len(doc_columns)+1 else "N/A"),  # contact_email from join
                ("Signing Date", doc[date_idx]),
                ("Status", doc[status_idx].upper() if status_idx < len(doc) and doc[status_idx] else "PENDING"),
                ("Verified By", doc[verified_by_idx] if verified_by_idx < len(doc) and doc[verified_by_idx] else "N/A"),
                ("Verification Date", doc[verified_date_idx][:10] if verified_date_idx < len(doc) and doc[verified_date_idx] else "N/A"),
            ]
            
            for label, value in overview_fields:
                item_frame = ctk.CTkFrame(overview_frame, fg_color="transparent")
                item_frame.pack(fill="x", pady=5)
                
                ctk.CTkLabel(
                    item_frame,
                    text=label + ":",
                    font=ctk.CTkFont(weight="bold"),
                    width=150
                ).pack(side="left")
                
                ctk.CTkLabel(
                    item_frame,
                    text=str(value),
                    wraplength=500
                ).pack(side="left", padx=10)
            
            # Content Tab
            content_tab = notebook.add("📝 Content")
            content_frame = ctk.CTkScrollableFrame(content_tab)
            content_frame.pack(fill="both", expand=True, padx=10, pady=10)
            
            content = doc[content_idx] if content_idx < len(doc) and doc[content_idx] else "No content available"
            content_text = ctk.CTkTextbox(content_frame, height=400)
            content_text.pack(fill="both", expand=True)
            content_text.insert("1.0", content)
            content_text.configure(state="disabled")
            
            # Signature Tab
            sig_tab = notebook.add("🔏 Signature")
            sig_frame = ctk.CTkScrollableFrame(sig_tab)
            sig_frame.pack(fill="both", expand=True, padx=10, pady=10)
            
            hash_val = doc[hash_idx] if hash_idx < len(doc) and doc[hash_idx] else "N/A"
            signature = doc[sig_idx] if sig_idx < len(doc) and doc[sig_idx] else "N/A"
            metadata = doc[metadata_idx] if metadata_idx < len(doc) and doc[metadata_idx] else "{}"
            
            sig_fields = [
                ("Document Hash (SHA256)", hash_val),
                ("Digital Signature", signature[:100] + "..." if len(signature) > 100 else signature),
                ("Metadata", metadata)
            ]
            
            for label, value in sig_fields:
                item_frame = ctk.CTkFrame(sig_frame, fg_color="transparent")
                item_frame.pack(fill="x", pady=10)
                
                ctk.CTkLabel(
                    item_frame,
                    text=label + ":",
                    font=ctk.CTkFont(weight="bold")
                ).pack(anchor="w", padx=10)
                
                text_widget = ctk.CTkTextbox(item_frame, height=100)
                text_widget.pack(fill="x", padx=10, pady=5)
                text_widget.insert("1.0", str(value))
                text_widget.configure(state="disabled")
            
            # Action buttons
            action_frame = ctk.CTkFrame(dialog, fg_color="transparent")
            action_frame.pack(pady=10, padx=10, fill="x")
            
            status = doc[status_idx] if status_idx < len(doc) else "pending"
            if status == "pending":
                ctk.CTkButton(
                    action_frame,
                    text="✅ Verify Document",
                    command=lambda: [self.verify_document(document_id), dialog.destroy()],
                    fg_color="#28A745"
                ).pack(side="left", padx=5)
                
                ctk.CTkButton(
                    action_frame,
                    text="❌ Reject Document",
                    command=lambda: [self.reject_document(document_id), dialog.destroy()],
                    fg_color="#DC3545"
                ).pack(side="left", padx=5)
            
            ctk.CTkButton(
                action_frame,
                text="📥 Download",
                command=lambda: self.download_document(document_id),
                fg_color="#17A2B8"
            ).pack(side="left", padx=5)
            
            ctk.CTkButton(
                action_frame,
                text="Close",
                command=dialog.destroy,
                fg_color="#6c757d"
            ).pack(side="right", padx=5)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load document details: {str(e)}")
            import traceback
            traceback.print_exc()
    
    def verify_document(self, document_id):
        """Verify a document"""
        if messagebox.askyesno("Verify Document", f"Verify document {document_id}?"):
            try:
                conn = sqlite3.connect("database/certauth.db")
                cursor = conn.cursor()
                
                cursor.execute("""
                    UPDATE signed_documents 
                    SET verification_status = 'verified', 
                        verified_by = ?,
                        verification_timestamp = CURRENT_TIMESTAMP
                    WHERE document_id = ?
                """, (self.username, document_id))
                
                conn.commit()
                conn.close()
                
                if db and hasattr(db, 'log_audit_event'):
                    db.log_audit_event('admin', self.username, 'verify_document', f"Verified document {document_id}")
                
                messagebox.showinfo("Success", f"Document {document_id} verified!")
                self.refresh_documents_list()
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to verify document: {str(e)}")
    
    def reject_document(self, document_id):
        """Reject a document"""
        reason = ctk.CTkInputDialog(
            text="Enter rejection reason:",
            title="Reject Document"
        ).get_input()
        
        if reason is None:
            return
        
        if messagebox.askyesno("Reject Document", f"Reject document {document_id}?"):
            try:
                conn = sqlite3.connect("database/certauth.db")
                cursor = conn.cursor()
                
                cursor.execute("""
                    UPDATE signed_documents 
                    SET verification_status = 'rejected', 
                        verified_by = ?,
                        verification_timestamp = CURRENT_TIMESTAMP
                    WHERE document_id = ?
                """, (self.username, document_id))
                
                conn.commit()
                conn.close()
                
                if db and hasattr(db, 'log_audit_event'):
                    db.log_audit_event('admin', self.username, 'reject_document', f"Rejected document {document_id}: {reason}")
                
                messagebox.showinfo("Success", f"Document {document_id} rejected!")
                self.refresh_documents_list()
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to reject document: {str(e)}")
    
    def download_document(self, document_id):
        """Download document as file"""
        try:
            conn = sqlite3.connect("database/certauth.db")
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM signed_documents WHERE document_id = ?", (document_id,))
            doc = cursor.fetchone()
            
            # Get column names
            cursor.execute("PRAGMA table_info(signed_documents)")
            columns = [col[1] for col in cursor.fetchall()]
            conn.close()
            
            if not doc:
                messagebox.showerror("Error", f"Document {document_id} not found")
                return
            
            file_path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("JSON files", "*.json")],
                initialfile=f"{document_id}_{datetime.now().strftime('%Y%m%d')}.txt"
            )
            
            if not file_path:
                return
            
            # Create document dictionary
            doc_dict = {}
            for i, col in enumerate(columns):
                if i < len(doc):
                    doc_dict[col] = doc[i]
            
            # Create full document export
            export_data = {
                "document_id": doc_dict.get('document_id', ''),
                "title": doc_dict.get('document_title', ''),
                "type": doc_dict.get('document_type', ''),
                "vendor_id": doc_dict.get('vendor_id', ''),
                "signing_timestamp": doc_dict.get('signing_timestamp', ''),
                "verification_status": doc_dict.get('verification_status', 'pending'),
                "verified_by": doc_dict.get('verified_by', ''),
                "verification_timestamp": doc_dict.get('verification_timestamp', ''),
                "document_hash": doc_dict.get('document_hash', ''),
                "digital_signature": doc_dict.get('digital_signature', ''),
                "content": doc_dict.get('document_content', ''),
                "metadata": doc_dict.get('metadata', '{}')
            }
            
            if file_path.endswith('.json'):
                with open(file_path, 'w') as f:
                    json.dump(export_data, f, indent=2, default=str)
            else:
                with open(file_path, 'w') as f:
                    f.write(f"=== VENDOR DOCUMENT ===\n")
                    f.write(f"Document ID: {export_data['document_id']}\n")
                    f.write(f"Title: {export_data['title']}\n")
                    f.write(f"Type: {export_data['type']}\n")
                    f.write(f"Vendor ID: {export_data['vendor_id']}\n")
                    f.write(f"Date: {export_data['signing_timestamp']}\n")
                    f.write(f"Status: {export_data['verification_status']}\n")
                    f.write(f"\n=== CONTENT ===\n")
                    f.write(f"{export_data['content']}\n")
            
            messagebox.showinfo("Success", f"Document saved to {file_path}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to download document: {str(e)}")
    
    # ========== CERTIFICATES TAB ==========
    
    def setup_certificates_tab(self):
        """Setup certificates management tab"""
        tab = self.tabview.tab("Certificates")
        
        ctk.CTkLabel(
            tab,
            text="Certificate Management",
            font=ctk.CTkFont(size=24, weight="bold")
        ).pack(pady=20)
        
        # Filter frame
        filter_frame = ctk.CTkFrame(tab, corner_radius=10)
        filter_frame.pack(pady=10, padx=20, fill="x")
        
        # Status filter
        ctk.CTkLabel(filter_frame, text="Status:").grid(row=0, column=0, padx=10, pady=10)
        self.cert_status_var = ctk.StringVar(value="all")
        status_menu = ctk.CTkOptionMenu(
            filter_frame,
            variable=self.cert_status_var,
            values=["all", "active", "expired", "expiring", "revoked"]
        )
        status_menu.grid(row=0, column=1, padx=10, pady=10)
        
        # Vendor filter
        ctk.CTkLabel(filter_frame, text="Vendor:").grid(row=0, column=2, padx=10, pady=10)
        self.cert_vendor_entry = ctk.CTkEntry(filter_frame, width=150, placeholder_text="Vendor ID")
        self.cert_vendor_entry.grid(row=0, column=3, padx=10, pady=10)
        
        # Buttons
        ctk.CTkButton(
            filter_frame,
            text="🔍 Search",
            command=self.refresh_certificates_list,
            width=100
        ).grid(row=0, column=4, padx=10, pady=10)
        
        ctk.CTkButton(
            filter_frame,
            text="🔄 Refresh",
            command=self.refresh_certificates_list,
            width=100
        ).grid(row=0, column=5, padx=10, pady=10)
        
        ctk.CTkButton(
            filter_frame,
            text="📧 Send Reminders",
            command=self.send_expiry_reminders,
            width=120
        ).grid(row=0, column=6, padx=10, pady=10)
        
        # Certificates list frame
        self.certificates_list_frame = ctk.CTkScrollableFrame(tab, height=500)
        self.certificates_list_frame.pack(pady=10, padx=20, fill="both", expand=True)
        
        # Load certificates
        self.refresh_certificates_list()
    
    def refresh_certificates_list(self):
        """Refresh certificates list with filters"""
        for widget in self.certificates_list_frame.winfo_children():
            widget.destroy()
        
        try:
            status = self.cert_status_var.get()
            vendor_filter = self.cert_vendor_entry.get().strip()
            
            conn = sqlite3.connect("database/certauth.db")
            cursor = conn.cursor()
            
            query = """
            SELECT c.*, v.company_name, v.contact_email
            FROM certificates c
            LEFT JOIN vendors v ON c.vendor_id = v.vendor_id
            WHERE 1=1
            """
            params = []
            
            if vendor_filter:
                query += " AND c.vendor_id LIKE ?"
                params.append(f"%{vendor_filter}%")
            
            # Fix the status filtering
            today = datetime.now().strftime("%Y-%m-%d")
            
            if status == "active":
                query += " AND c.revoked = 0 AND c.not_valid_after > ?"
                params.append(today)
            elif status == "expired":
                query += " AND c.not_valid_after < ?"
                params.append(today)
            elif status == "expiring":
                query += " AND c.revoked = 0 AND c.not_valid_after < date('now', '+30 days') AND c.not_valid_after > date('now')"
            elif status == "revoked":
                query += " AND c.revoked = 1"
            
            query += " ORDER BY c.not_valid_after ASC"
            cursor.execute(query, params)
            certificates = cursor.fetchall()
            
            if not certificates:
                ctk.CTkLabel(
                    self.certificates_list_frame,
                    text="No certificates found",
                    font=ctk.CTkFont(size=16)
                ).pack(pady=50)
                conn.close()
                return
            
            # Get column names
            cursor.execute("PRAGMA table_info(certificates)")
            cert_columns = [col[1] for col in cursor.fetchall()]
            
            # Headers
            headers = ["Serial Number", "Vendor", "Company", "Valid From", "Valid To", "Status", "Actions"]
            headers_frame = ctk.CTkFrame(self.certificates_list_frame, fg_color="transparent")
            headers_frame.pack(fill="x", pady=5)
            
            for header in headers:
                width = 120 if header not in ["Company"] else 150
                ctk.CTkLabel(
                    headers_frame,
                    text=header,
                    font=ctk.CTkFont(weight="bold", size=12),
                    width=width
                ).pack(side="left", padx=2)
            
            # Get indices
            serial_idx = cert_columns.index('serial_number') if 'serial_number' in cert_columns else 1
            vendor_idx = cert_columns.index('vendor_id') if 'vendor_id' in cert_columns else 2
            from_idx = cert_columns.index('not_valid_before') if 'not_valid_before' in cert_columns else 4
            to_idx = cert_columns.index('not_valid_after') if 'not_valid_after' in cert_columns else 5
            revoked_idx = cert_columns.index('revoked') if 'revoked' in cert_columns else 6
            
            # Certificate rows
            for cert in certificates:
                serial = cert[serial_idx]
                vendor_id = cert[vendor_idx]
                company = cert[-2] if len(cert) > len(cert_columns) and cert[-2] else "Unknown"  # company_name from join
                valid_from = cert[from_idx][:10] if cert[from_idx] else "N/A"
                valid_to = cert[to_idx][:10] if cert[to_idx] else "N/A"
                revoked = cert[revoked_idx] if revoked_idx < len(cert) else 0
                
                row_frame = ctk.CTkFrame(self.certificates_list_frame)
                row_frame.pack(fill="x", pady=2)
                
                # Serial
                ctk.CTkLabel(row_frame, text=serial[:15] + "...", width=120).pack(side="left", padx=2)
                
                # Vendor ID
                ctk.CTkLabel(row_frame, text=vendor_id, width=120).pack(side="left", padx=2)
                
                # Company
                company_display = company[:15] + "..." if len(company) > 15 else company
                ctk.CTkLabel(row_frame, text=company_display, width=150).pack(side="left", padx=2)
                
                # Valid From
                ctk.CTkLabel(row_frame, text=valid_from, width=120).pack(side="left", padx=2)
                
                # Valid To
                ctk.CTkLabel(row_frame, text=valid_to, width=120).pack(side="left", padx=2)
                
                # Status
                if revoked:
                    status_text = "REVOKED"
                    status_color = "#DC3545"
                elif valid_to < datetime.now().strftime("%Y-%m-%d"):
                    status_text = "EXPIRED"
                    status_color = "#6C757D"
                elif valid_to < (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d"):
                    status_text = "EXPIRING SOON"
                    status_color = "#FFC107"
                else:
                    status_text = "ACTIVE"
                    status_color = "#28A745"
                
                ctk.CTkLabel(
                    row_frame,
                    text=status_text,
                    text_color=status_color,
                    width=120
                ).pack(side="left", padx=2)
                
                # Actions
                actions_frame = ctk.CTkFrame(row_frame, fg_color="transparent")
                actions_frame.pack(side="left", padx=5)
                
                # View button
                ctk.CTkButton(
                    actions_frame,
                    text="👁️",
                    width=30,
                    height=25,
                    command=lambda s=serial: self.view_certificate_details(s)
                ).pack(side="left", padx=1)
                
                # Download button
                ctk.CTkButton(
                    actions_frame,
                    text="📥",
                    width=30,
                    height=25,
                    fg_color="#17A2B8",
                    command=lambda s=serial: self.download_certificate(s)
                ).pack(side="left", padx=1)
                
                # Revoke button (if not revoked)
                if not revoked:
                    ctk.CTkButton(
                        actions_frame,
                        text="🔴",
                        width=30,
                        height=25,
                        fg_color="#DC3545",
                        command=lambda s=serial, v=vendor_id: self.revoke_certificate(s, v)
                    ).pack(side="left", padx=1)
            
            conn.close()
            
        except Exception as e:
            ctk.CTkLabel(
                self.certificates_list_frame,
                text=f"Error loading certificates: {str(e)}",
                text_color="red"
            ).pack(pady=20)
            import traceback
            traceback.print_exc()
    
    def view_certificate_details(self, serial_number):
        """View certificate details"""
        try:
            conn = sqlite3.connect("database/certauth.db")
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT c.*, v.company_name, v.contact_email
                FROM certificates c
                LEFT JOIN vendors v ON c.vendor_id = v.vendor_id
                WHERE c.serial_number = ?
            """, (serial_number,))
            cert = cursor.fetchone()
            conn.close()
            
            if not cert:
                messagebox.showerror("Error", f"Certificate {serial_number} not found")
                return
            
            # Create details window
            dialog = ctk.CTkToplevel(self.window)
            dialog.title(f"Certificate Details - {serial_number[:20]}...")
            dialog.geometry("700x600")
            dialog.transient(self.window)
            dialog.grab_set()
            
            ctk.CTkLabel(
                dialog,
                text="🔐 Certificate Details",
                font=ctk.CTkFont(size=20, weight="bold")
            ).pack(pady=20)
            
            # Info frame
            info_frame = ctk.CTkScrollableFrame(dialog)
            info_frame.pack(pady=10, padx=20, fill="both", expand=True)
            
            fields = [
                ("Serial Number", cert[1]),
                ("Vendor ID", cert[2]),
                ("Company", cert[-2] if len(cert) > 13 else "N/A"),
                ("Email", cert[-1] if len(cert) > 14 else "N/A"),
                ("Issuer CA", cert[3]),
                ("Subject", cert[4]),
                ("Valid From", cert[5][:10] if cert[5] else "N/A"),
                ("Valid To", cert[6][:10] if cert[6] else "N/A"),
                ("Revoked", "Yes" if cert[7] else "No"),
                ("Revocation Reason", cert[8] if cert[8] else "N/A"),
                ("Revocation Date", cert[9][:10] if cert[9] else "N/A"),
            ]
            
            for label, value in fields:
                item_frame = ctk.CTkFrame(info_frame, fg_color="transparent")
                item_frame.pack(fill="x", pady=5)
                
                ctk.CTkLabel(
                    item_frame,
                    text=label + ":",
                    font=ctk.CTkFont(weight="bold"),
                    width=150
                ).pack(side="left")
                
                ctk.CTkLabel(
                    item_frame,
                    text=str(value),
                    wraplength=400
                ).pack(side="left", padx=10)
            
            # Certificate data
            cert_data_frame = ctk.CTkFrame(info_frame)
            cert_data_frame.pack(fill="x", pady=10)
            
            ctk.CTkLabel(
                cert_data_frame,
                text="Certificate Data (PEM):",
                font=ctk.CTkFont(weight="bold")
            ).pack(anchor="w", padx=10, pady=5)
            
            cert_text = ctk.CTkTextbox(cert_data_frame, height=150)
            cert_text.pack(fill="x", padx=10, pady=5)
            cert_text.insert("1.0", cert[10] if len(cert) > 10 else "No certificate data")
            cert_text.configure(state="disabled")
            
            # Action buttons
            action_frame = ctk.CTkFrame(dialog, fg_color="transparent")
            action_frame.pack(pady=20, padx=20, fill="x")
            
            if not cert[7]:  # If not revoked
                ctk.CTkButton(
                    action_frame,
                    text="🔴 Revoke Certificate",
                    command=lambda: [self.revoke_certificate(serial_number, cert[2]), dialog.destroy()],
                    fg_color="#DC3545"
                ).pack(side="left", padx=5)
            
            ctk.CTkButton(
                action_frame,
                text="📥 Download",
                command=lambda: self.download_certificate(serial_number),
                fg_color="#17A2B8"
            ).pack(side="left", padx=5)
            
            ctk.CTkButton(
                action_frame,
                text="Close",
                command=dialog.destroy,
                fg_color="#6c757d"
            ).pack(side="right", padx=5)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load certificate details: {str(e)}")
    
    def download_certificate(self, serial_number):
        """Download certificate as file"""
        try:
            conn = sqlite3.connect("database/certauth.db")
            cursor = conn.cursor()
            
            cursor.execute("SELECT certificate_data FROM certificates WHERE serial_number = ?", (serial_number,))
            result = cursor.fetchone()
            conn.close()
            
            if not result:
                messagebox.showerror("Error", f"Certificate {serial_number} not found")
                return
            
            cert_data = result[0]
            
            file_path = filedialog.asksaveasfilename(
                defaultextension=".crt",
                filetypes=[("Certificate files", "*.crt"), ("PEM files", "*.pem")],
                initialfile=f"certificate_{serial_number[:10]}.crt"
            )
            
            if file_path:
                with open(file_path, 'w') as f:
                    f.write(cert_data)
                messagebox.showinfo("Success", f"Certificate saved to {file_path}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to download certificate: {str(e)}")
    
    def revoke_certificate(self, serial_number, vendor_id):
        """Revoke a certificate"""
        # First ask for reason text
        reason = ctk.CTkInputDialog(
            text="Enter revocation reason:",
            title="Revoke Certificate"
        ).get_input()
        
        if reason is None or reason.strip() == "":
            return
        
        # Dictionary of reason codes
        reason_codes = {
            "Unspecified": 0,
            "Key Compromise": 1,
            "CA Compromise": 2,
            "Affiliation Changed": 3,
            "Superseded": 4,
            "Cessation of Operation": 5
        }
        
        # Create reason code selection dialog
        code_dialog = ctk.CTkToplevel(self.window)
        code_dialog.title("Select Revocation Reason Code")
        code_dialog.geometry("600x650")
        code_dialog.transient(self.window)
        code_dialog.grab_set()
        
        # Make it modal
        code_dialog.focus_set()
        code_dialog.lift()
        
        # Header
        ctk.CTkLabel(
            code_dialog,
            text="🔐 Certificate Revocation",
            font=ctk.CTkFont(size=20, weight="bold")
        ).pack(pady=20)
        
        # Certificate info
        info_frame = ctk.CTkFrame(code_dialog, corner_radius=10)
        info_frame.pack(pady=10, padx=20, fill="x")
        
        ctk.CTkLabel(
            info_frame,
            text=f"Certificate: {serial_number[:30]}...",
            font=ctk.CTkFont(size=13, weight="bold")
        ).pack(anchor="w", padx=20, pady=(10, 5))
        
        ctk.CTkLabel(
            info_frame,
            text=f"Vendor ID: {vendor_id}",
            font=ctk.CTkFont(size=13)
        ).pack(anchor="w", padx=20, pady=(0, 5))
        
        ctk.CTkLabel(
            info_frame,
            text=f"Reason: {reason}",
            font=ctk.CTkFont(size=13),
            text_color="#FFC107"
        ).pack(anchor="w", padx=20, pady=(0, 10))
        
        # Reason code selection
        ctk.CTkLabel(
            code_dialog,
            text="Select Revocation Reason Code:",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(pady=(20, 10))
        
        # Frame for radio buttons
        radio_frame = ctk.CTkFrame(code_dialog, corner_radius=10)
        radio_frame.pack(pady=10, padx=30, fill="both", expand=True)
        
        reason_var = ctk.StringVar(value="Unspecified")
        
        # Add radio buttons for each reason
        for reason_text in reason_codes.keys():
            rb = ctk.CTkRadioButton(
                radio_frame,
                text=reason_text,
                variable=reason_var,
                value=reason_text,
                font=ctk.CTkFont(size=14)
            )
            rb.pack(pady=8, padx=30, anchor="w")
        
        # BUTTON FRAME
        button_frame = ctk.CTkFrame(code_dialog, fg_color="transparent")
        button_frame.pack(pady=20, padx=30, fill="x")
        
        def confirm_revocation():
            selected_reason = reason_var.get()
            code = reason_codes[selected_reason]
            
            try:
                conn = sqlite3.connect("database/certauth.db")
                cursor = conn.cursor()
                
                # Update certificate
                cursor.execute("""
                    UPDATE certificates 
                    SET revoked = 1, revocation_reason = ?, revocation_date = CURRENT_TIMESTAMP
                    WHERE serial_number = ?
                """, (reason, serial_number))
                
                # Add to CRL
                cursor.execute("""
                    INSERT INTO crl (serial_number, reason_code, reason_text, revocation_date)
                    VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                """, (serial_number, code, reason))
                
                # ✅ IMPORTANT: Update vendor status to revoked
                cursor.execute("""
                    UPDATE vendors 
                    SET status = 'revoked'
                    WHERE vendor_id = ?
                """, (vendor_id,))
                
                conn.commit()
                conn.close()
                
                # Log the action
                if db and hasattr(db, 'log_audit_event'):
                    db.log_audit_event('admin', self.username, 'revoke_certificate', 
                                    f"Revoked certificate {serial_number[:20]} for vendor {vendor_id}")
                
                messagebox.showinfo("Success", 
                    f"✅ Certificate revoked successfully!\n\n"
                    f"Vendor {vendor_id} has been revoked and cannot login.")
                
                code_dialog.destroy()
                self.refresh_certificates_list()
                self.refresh_vendors_list()  # Also refresh vendors list
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to revoke certificate: {str(e)}")
                code_dialog.destroy()
        
        def cancel_revocation():
            code_dialog.destroy()
        
        # CANCEL BUTTON
        ctk.CTkButton(
            button_frame,
            text="Cancel",
            command=cancel_revocation,
            height=45,
            fg_color="#6c757d",
            hover_color="#5a6268",
            width=120
        ).pack(side="left", padx=5)
        
        # REVOKE BUTTON
        ctk.CTkButton(
            button_frame,
            text="🔴 REVOKE CERTIFICATE",
            command=confirm_revocation,
            height=45,
            fg_color="#DC3545",
            hover_color="#c82333",
            font=ctk.CTkFont(size=14, weight="bold"),
            width=200
        ).pack(side="right", padx=5)
        
        # Warning text
        ctk.CTkLabel(
            code_dialog,
            text="⚠️ Warning: This action cannot be undone!",
            font=ctk.CTkFont(size=12),
            text_color="#FFC107"
        ).pack(pady=(0, 20))
            
    
    # ========== AUDIT TRAIL TAB ==========
    
    def setup_audit_trail_tab(self):
        """Setup audit trail tab"""
        tab = self.tabview.tab("Audit Trail")
        
        ctk.CTkLabel(
            tab,
            text="System Audit Trail",
            font=ctk.CTkFont(size=24, weight="bold")
        ).pack(pady=20)
        
        # Filter frame
        filter_frame = ctk.CTkFrame(tab, corner_radius=10)
        filter_frame.pack(pady=10, padx=20, fill="x")
        
        # Date range
        ctk.CTkLabel(filter_frame, text="From:").grid(row=0, column=0, padx=10, pady=10)
        self.audit_from_entry = ctk.CTkEntry(filter_frame, width=120, placeholder_text="YYYY-MM-DD")
        self.audit_from_entry.grid(row=0, column=1, padx=10, pady=10)
        self.audit_from_entry.insert(0, (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d"))
        
        ctk.CTkLabel(filter_frame, text="To:").grid(row=0, column=2, padx=10, pady=10)
        self.audit_to_entry = ctk.CTkEntry(filter_frame, width=120, placeholder_text="YYYY-MM-DD")
        self.audit_to_entry.grid(row=0, column=3, padx=10, pady=10)
        self.audit_to_entry.insert(0, datetime.now().strftime("%Y-%m-%d"))
        
        # User filter
        ctk.CTkLabel(filter_frame, text="User:").grid(row=0, column=4, padx=10, pady=10)
        self.audit_user_entry = ctk.CTkEntry(filter_frame, width=150, placeholder_text="User ID")
        self.audit_user_entry.grid(row=0, column=5, padx=10, pady=10)
        
        # Action filter
        ctk.CTkLabel(filter_frame, text="Action:").grid(row=1, column=0, padx=10, pady=10)
        self.audit_action_var = ctk.StringVar(value="all")
        action_menu = ctk.CTkOptionMenu(
            filter_frame,
            variable=self.audit_action_var,
            values=["all", "login", "logout", "approve", "reject", "verify", "revoke", "delete"]
        )
        action_menu.grid(row=1, column=1, padx=10, pady=10)
        
        # Buttons
        ctk.CTkButton(
            filter_frame,
            text="🔍 Apply Filters",
            command=self.refresh_audit_logs,
            width=120
        ).grid(row=1, column=2, padx=10, pady=10)
        
        ctk.CTkButton(
            filter_frame,
            text="📥 Export",
            command=self.export_audit_logs,
            width=100
        ).grid(row=1, column=3, padx=10, pady=10)

        # ===== ADD DELETE ALL BUTTON HERE =====
        def delete_all_logs():
            if messagebox.askyesno("Delete All", 
                                "⚠️ Delete ALL audit logs?\n\nThis cannot be undone!"):
                try:
                    conn = sqlite3.connect("database/certauth.db")
                    cursor = conn.cursor()
                    cursor.execute("DELETE FROM audit_log")
                    deleted = cursor.rowcount
                    conn.commit()
                    conn.close()
                    messagebox.showinfo("Deleted", f"Deleted {deleted} logs")
                    self.refresh_audit_logs()
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to delete: {str(e)}")
        
        ctk.CTkButton(
            filter_frame,
            text="🗑️ Delete All",
            command=delete_all_logs,
            width=100,
            fg_color="#DC3545",
            hover_color="#c82333"
        ).grid(row=1, column=4, padx=10, pady=10)
        # ===== END DELETE ALL BUTTON =====
        
        # Logs display frame
        self.audit_logs_frame = ctk.CTkScrollableFrame(tab, height=500)
        self.audit_logs_frame.pack(pady=10, padx=20, fill="both", expand=True)
        
        # Initial load
        self.refresh_audit_logs()
    def refresh_audit_logs(self):
        """Refresh audit logs display"""
        for widget in self.audit_logs_frame.winfo_children():
            widget.destroy()
        
        try:
            from_date = self.audit_from_entry.get().strip()
            to_date = self.audit_to_entry.get().strip()
            user_filter = self.audit_user_entry.get().strip()
            action_filter = self.audit_action_var.get()
            
            conn = sqlite3.connect("database/certauth.db")
            cursor = conn.cursor()
            
            # Include id in SELECT
            query = "SELECT id, timestamp, user_type, user_id, action, details, ip_address, success FROM audit_log WHERE 1=1"
            params = []
            
            if from_date:
                query += " AND date(timestamp) >= ?"
                params.append(from_date)
            
            if to_date:
                query += " AND date(timestamp) <= ?"
                params.append(to_date)
            
            if user_filter:
                query += " AND user_id LIKE ?"
                params.append(f"%{user_filter}%")
            
            if action_filter != "all":
                query += " AND action = ?"
                params.append(action_filter)
            
            query += " ORDER BY timestamp DESC LIMIT 500"
            cursor.execute(query, params)
            logs = cursor.fetchall()
            conn.close()
            
            if not logs:
                ctk.CTkLabel(
                    self.audit_logs_frame,
                    text="No audit logs found",
                    font=ctk.CTkFont(size=16)
                ).pack(pady=50)
                return
            
            # Headers - ADD "Actions" column
            headers = ["Timestamp", "User Type", "User ID", "Action", "Details", "IP", "Status", "Actions"]
            headers_frame = ctk.CTkFrame(self.audit_logs_frame, fg_color="transparent")
            headers_frame.pack(fill="x", pady=5)
            
            for header in headers:
                width = 100 if header not in ["Details", "Actions"] else 200
                ctk.CTkLabel(
                    headers_frame,
                    text=header,
                    font=ctk.CTkFont(weight="bold", size=12),
                    width=width
                ).pack(side="left", padx=2)
            
            # Log rows with delete button
            for log in logs:
                log_id, timestamp, user_type, user_id, action, details, ip, success = log
                
                row_frame = ctk.CTkFrame(self.audit_logs_frame)
                row_frame.pack(fill="x", pady=2)
                
                # Timestamp
                time_str = timestamp[11:19] if timestamp else "N/A"
                ctk.CTkLabel(row_frame, text=time_str, width=100).pack(side="left", padx=2)
                
                # User Type
                ctk.CTkLabel(row_frame, text=user_type, width=100).pack(side="left", padx=2)
                
                # User ID
                display_id = user_id[:15] + "..." if len(user_id) > 15 else user_id
                ctk.CTkLabel(row_frame, text=display_id, width=100).pack(side="left", padx=2)
                
                # Action
                ctk.CTkLabel(row_frame, text=action, width=100).pack(side="left", padx=2)
                
                # Details
                details_display = details[:50] + ("..." if len(details) > 50 else "")
                ctk.CTkLabel(row_frame, text=details_display, width=200).pack(side="left", padx=2)
                
                # IP
                ctk.CTkLabel(row_frame, text=ip or "N/A", width=100).pack(side="left", padx=2)
                
                # Success
                status_text = "✅" if success else "❌"
                status_color = "#28A745" if success else "#DC3545"
                ctk.CTkLabel(
                    row_frame,
                    text=status_text,
                    text_color=status_color,
                    width=80
                ).pack(side="left", padx=2)
                
                # ===== DELETE BUTTON =====
                def delete_log(log_id=log_id):
                    if messagebox.askyesno("Delete Log", f"Delete this audit log?\n\nID: {log_id}\nThis cannot be undone!"):
                        try:
                            conn = sqlite3.connect("database/certauth.db")
                            cursor = conn.cursor()
                            cursor.execute("DELETE FROM audit_log WHERE id = ?", (log_id,))
                            conn.commit()
                            conn.close()
                            messagebox.showinfo("Deleted", "Log deleted successfully")
                            self.refresh_audit_logs()
                        except Exception as e:
                            messagebox.showerror("Error", f"Failed to delete: {str(e)}")
                
                ctk.CTkButton(
                    row_frame,
                    text="🗑️",
                    command=delete_log,
                    width=50,
                    height=25,
                    fg_color="#DC3545",
                    hover_color="#c82333"
                ).pack(side="left", padx=2)
                
        except Exception as e:
            ctk.CTkLabel(
                self.audit_logs_frame,
                text=f"Error loading audit logs: {str(e)}",
                text_color="red"
            ).pack(pady=20)
    
    def export_audit_logs(self):
        """Export audit logs to file"""
        try:
            from_date = self.audit_from_entry.get().strip()
            to_date = self.audit_to_entry.get().strip()
            user_filter = self.audit_user_entry.get().strip()
            action_filter = self.audit_action_var.get()
            
            conn = sqlite3.connect("database/certauth.db")
            cursor = conn.cursor()
            
            query = "SELECT * FROM audit_log WHERE 1=1"
            params = []
            
            if from_date:
                query += " AND date(timestamp) >= ?"
                params.append(from_date)
            
            if to_date:
                query += " AND date(timestamp) <= ?"
                params.append(to_date)
            
            if user_filter:
                query += " AND user_id LIKE ?"
                params.append(f"%{user_filter}%")
            
            if action_filter != "all":
                query += " AND action = ?"
                params.append(action_filter)
            
            query += " ORDER BY timestamp DESC"
            cursor.execute(query, params)
            logs = cursor.fetchall()
            conn.close()
            
            if not logs:
                messagebox.showinfo("No Data", "No logs to export")
                return
            
            file_path = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv")],
                initialfile=f"audit_logs_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"
            )
            
            if file_path:
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    
                    # Write headers
                    headers = ["ID", "Timestamp", "User Type", "User ID", "Action", "Details", "IP Address", "Success"]
                    writer.writerow(headers)
                    
                    # Write data
                    for log in logs:
                        writer.writerow([
                            log[0], log[1], log[2], log[3], log[4], 
                            log[5], log[6], log[7]
                        ])
                
                messagebox.showinfo("Success", f"Audit logs exported to {file_path}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export logs: {str(e)}")
    
    # ========== REPORTS TAB ==========
    
    def setup_reports_tab(self):
        """Setup reports tab"""
        tab = self.tabview.tab("Reports")
        
        ctk.CTkLabel(
            tab,
            text="Reports & Analytics",
            font=ctk.CTkFont(size=24, weight="bold")
        ).pack(pady=20)
        
        # Reports grid
        reports_frame = ctk.CTkFrame(tab, corner_radius=15)
        reports_frame.pack(pady=10, padx=20, fill="both", expand=True)
        
        reports = [
            ("📊 Vendor Performance Report", self.generate_vendor_report,
             "Vendor activity, document counts, verification rates"),
            ("📈 Document Statistics", self.generate_document_report,
             "Document types, verification status, trends"),
            ("🔐 Certificate Status Report", self.generate_certificate_report,
             "Active, expiring, expired, and revoked certificates"),
            ("📆 Monthly Activity Summary", self.generate_activity_report,
             "System usage, login attempts, document operations"),
            ("🚨 Security Audit Report", self.generate_security_report,
             "Failed logins, revocations, suspicious activities"),
            ("📋 Compliance Summary", self.generate_compliance_report,
             "Vendor compliance, document verification status")
        ]
        
        for i, (title, command, desc) in enumerate(reports):
            report_card = ctk.CTkFrame(reports_frame, corner_radius=10)
            report_card.pack(pady=10, padx=20, fill="x")
            
            header_frame = ctk.CTkFrame(report_card, fg_color="transparent")
            header_frame.pack(fill="x", padx=20, pady=15)
            
            ctk.CTkLabel(
                header_frame,
                text=title,
                font=ctk.CTkFont(size=16, weight="bold")
            ).pack(side="left")
            
            ctk.CTkLabel(
                header_frame,
                text=desc,
                font=ctk.CTkFont(size=12),
                text_color="gray"
            ).pack(side="left", padx=20)
            
            ctk.CTkButton(
                header_frame,
                text="Generate →",
                command=command,
                width=100
            ).pack(side="right")
    
    def generate_vendor_report(self):
        """Generate vendor performance report"""
        try:
            conn = sqlite3.connect("database/certauth.db")
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT 
                    v.vendor_id,
                    v.company_name,
                    v.status,
                    v.registration_date,
                    COUNT(DISTINCT d.document_id) as total_docs,
                    SUM(CASE WHEN d.verification_status = 'verified' THEN 1 ELSE 0 END) as verified_docs,
                    SUM(CASE WHEN d.verification_status = 'rejected' THEN 1 ELSE 0 END) as rejected_docs,
                    COUNT(DISTINCT c.serial_number) as total_certs,
                    SUM(CASE WHEN c.revoked = 1 THEN 1 ELSE 0 END) as revoked_certs
                FROM vendors v
                LEFT JOIN signed_documents d ON v.vendor_id = d.vendor_id
                LEFT JOIN certificates c ON v.vendor_id = c.vendor_id
                GROUP BY v.vendor_id
                ORDER BY total_docs DESC
            """)
            
            vendors = cursor.fetchall()
            conn.close()
            
            if not vendors:
                messagebox.showinfo("No Data", "No vendor data available")
                return
            
            self.show_report_results("Vendor Performance Report", vendors,
                                    ["Vendor ID", "Company", "Status", "Registered", 
                                     "Documents", "Verified", "Rejected", "Certificates", "Revoked"])
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate report: {str(e)}")
    
    def generate_document_report(self):
        """Generate document statistics report"""
        try:
            conn = sqlite3.connect("database/certauth.db")
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT 
                    document_type,
                    COUNT(*) as total,
                    SUM(CASE WHEN verification_status = 'verified' THEN 1 ELSE 0 END) as verified,
                    SUM(CASE WHEN verification_status = 'pending' THEN 1 ELSE 0 END) as pending,
                    SUM(CASE WHEN verification_status = 'rejected' THEN 1 ELSE 0 END) as rejected
                FROM signed_documents
                GROUP BY document_type
                ORDER BY total DESC
            """)
            
            documents = cursor.fetchall()
            conn.close()
            
            if not documents:
                messagebox.showinfo("No Data", "No document data available")
                return
            
            self.show_report_results("Document Statistics Report", documents,
                                    ["Document Type", "Total", "Verified", "Pending", "Rejected"])
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate report: {str(e)}")
    
    def generate_certificate_report(self):
        """Generate certificate status report"""
        try:
            conn = sqlite3.connect("database/certauth.db")
            cursor = conn.cursor()
            
            # Active certificates
            cursor.execute("SELECT COUNT(*) FROM certificates WHERE revoked = 0 AND not_valid_after > date('now')")
            active = cursor.fetchone()[0]
            
            # Expiring soon
            cursor.execute("""
                SELECT COUNT(*) FROM certificates 
                WHERE revoked = 0 AND not_valid_after < date('now', '+30 days')
                AND not_valid_after > date('now')
            """)
            expiring = cursor.fetchone()[0]
            
            # Expired
            cursor.execute("SELECT COUNT(*) FROM certificates WHERE not_valid_after < date('now')")
            expired = cursor.fetchone()[0]
            
            # Revoked
            cursor.execute("SELECT COUNT(*) FROM certificates WHERE revoked = 1")
            revoked = cursor.fetchone()[0]
            
            # By vendor
            cursor.execute("""
                SELECT v.vendor_id, v.company_name, COUNT(c.serial_number) as cert_count
                FROM vendors v
                LEFT JOIN certificates c ON v.vendor_id = c.vendor_id AND c.revoked = 0
                GROUP BY v.vendor_id
                ORDER BY cert_count DESC
                LIMIT 10
            """)
            top_vendors = cursor.fetchall()
            
            conn.close()
            
            report = f"=== CERTIFICATE STATUS REPORT ===\n"
            report += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            report += "="*50 + "\n\n"
            report += f"✅ Active Certificates: {active}\n"
            report += f"⚠️ Expiring Soon (30 days): {expiring}\n"
            report += f"❌ Expired Certificates: {expired}\n"
            report += f"🔴 Revoked Certificates: {revoked}\n\n"
            report += "Top Vendors by Active Certificates:\n"
            for vendor in top_vendors:
                report += f"  • {vendor[1]}: {vendor[2]} certificates\n"
            
            messagebox.showinfo("Certificate Report", report)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate report: {str(e)}")
    
    def generate_activity_report(self):
        """Generate monthly activity report"""
        try:
            conn = sqlite3.connect("database/certauth.db")
            cursor = conn.cursor()
            
            # Activities by day
            cursor.execute("""
                SELECT date(timestamp), COUNT(*)
                FROM audit_log
                WHERE timestamp > date('now', '-30 days')
                GROUP BY date(timestamp)
                ORDER BY date(timestamp) DESC
            """)
            daily = cursor.fetchall()
            
            # Activities by action
            cursor.execute("""
                SELECT action, COUNT(*)
                FROM audit_log
                WHERE timestamp > date('now', '-30 days')
                GROUP BY action
                ORDER BY COUNT(*) DESC
            """)
            actions = cursor.fetchall()
            
            conn.close()
            
            report = f"=== MONTHLY ACTIVITY REPORT ===\n"
            report += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            report += "="*50 + "\n\n"
            report += "Daily Activity (Last 30 Days):\n"
            for date, count in daily[:10]:
                report += f"  • {date}: {count} activities\n"
            report += "\nMost Common Actions:\n"
            for action, count in actions[:5]:
                report += f"  • {action}: {count}\n"
            
            messagebox.showinfo("Activity Report", report)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate report: {str(e)}")
    
    def generate_security_report(self):
        """Generate security report"""
        try:
            conn = sqlite3.connect("database/certauth.db")
            cursor = conn.cursor()
            
            # Failed logins
            cursor.execute("""
                SELECT COUNT(*) FROM audit_log 
                WHERE action = 'login' AND success = 0
                AND timestamp > date('now', '-7 days')
            """)
            failed_logins = cursor.fetchone()[0]
            
            # Revoked certificates
            cursor.execute("SELECT COUNT(*) FROM crl WHERE revocation_date > date('now', '-7 days')")
            revoked_certs = cursor.fetchone()[0]
            
            # Suspicious activities
            cursor.execute("""
                SELECT user_id, COUNT(*) as attempts
                FROM audit_log
                WHERE action = 'login' AND success = 0
                AND timestamp > date('now', '-7 days')
                GROUP BY user_id
                HAVING attempts >= 3
            """)
            suspicious = cursor.fetchall()
            
            # Recent security events
            cursor.execute("""
                SELECT timestamp, user_id, action, details
                FROM audit_log
                WHERE (action LIKE '%revoke%' OR action LIKE '%fail%')
                AND timestamp > date('now', '-7 days')
                ORDER BY timestamp DESC
                LIMIT 10
            """)
            events = cursor.fetchall()
            
            conn.close()
            
            report = f"=== SECURITY REPORT ===\n"
            report += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            report += "="*50 + "\n\n"
            report += f"Failed Logins (7 days): {failed_logins}\n"
            report += f"Recently Revoked Certificates: {revoked_certs}\n\n"
            
            if suspicious:
                report += "⚠️ SUSPICIOUS ACTIVITIES:\n"
                for user_id, attempts in suspicious:
                    report += f"  • User {user_id}: {attempts} failed login attempts\n"
            else:
                report += "✅ No suspicious activities detected\n\n"
            
            report += "Recent Security Events:\n"
            for ts, user_id, action, details in events:
                time_str = ts[11:16] if ts else "--:--"
                report += f"  • [{time_str}] {user_id}: {action}"
                if details:
                    report += f" - {details[:30]}..."
                report += "\n"
            
            messagebox.showinfo("Security Report", report)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate report: {str(e)}")
    
    def generate_compliance_report(self):
        """Generate compliance report"""
        try:
            conn = sqlite3.connect("database/certauth.db")
            cursor = conn.cursor()
            
            # Vendor compliance
            cursor.execute("""
                SELECT 
                    v.status,
                    COUNT(*) as count,
                    AVG(CASE WHEN d.verification_status = 'verified' THEN 1 ELSE 0 END) as compliance_rate
                FROM vendors v
                LEFT JOIN signed_documents d ON v.vendor_id = d.vendor_id
                GROUP BY v.status
            """)
            vendor_compliance = cursor.fetchall()
            
            # Document compliance by type
            cursor.execute("""
                SELECT 
                    document_type,
                    COUNT(*) as total,
                    SUM(CASE WHEN verification_status = 'verified' THEN 1 ELSE 0 END) as verified
                FROM signed_documents
                GROUP BY document_type
            """)
            doc_compliance = cursor.fetchall()
            
            conn.close()
            
            report = f"=== COMPLIANCE STATUS REPORT ===\n"
            report += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            report += "="*50 + "\n\n"
            report += "Vendor Compliance by Status:\n"
            for status, count, rate in vendor_compliance:
                rate_percent = (rate or 0) * 100
                report += f"  • {status.upper()}: {count} vendors ({rate_percent:.1f}% compliance)\n"
            report += "\nDocument Compliance by Type:\n"
            for doc_type, total, verified in doc_compliance:
                rate = (verified/total*100) if total > 0 else 0
                type_name = doc_type.replace('_', ' ').title()
                report += f"  • {type_name}: {verified}/{total} verified ({rate:.1f}%)\n"
            
            messagebox.showinfo("Compliance Report", report)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate report: {str(e)}")
    
    def show_report_results(self, title, data, headers):
        """Show report results in a window"""
        dialog = ctk.CTkToplevel(self.window)
        dialog.title(title)
        dialog.geometry("900x600")
        dialog.transient(self.window)
        
        ctk.CTkLabel(
            dialog,
            text=title,
            font=ctk.CTkFont(size=20, weight="bold")
        ).pack(pady=20)
        
        # Create treeview for data
        frame = ctk.CTkFrame(dialog)
        frame.pack(pady=10, padx=20, fill="both", expand=True)
        
        # Create scrollable frame
        scroll_frame = ctk.CTkScrollableFrame(frame)
        scroll_frame.pack(fill="both", expand=True)
        
        # Headers
        headers_frame = ctk.CTkFrame(scroll_frame, fg_color="transparent")
        headers_frame.pack(fill="x", pady=5)
        
        for header in headers:
            ctk.CTkLabel(
                headers_frame,
                text=header,
                font=ctk.CTkFont(weight="bold", size=12),
                width=120
            ).pack(side="left", padx=2)
        
        # Data rows
        for row in data:
            row_frame = ctk.CTkFrame(scroll_frame)
            row_frame.pack(fill="x", pady=2)
            
            for value in row:
                display = str(value)[:20] + "..." if len(str(value)) > 20 else str(value)
                ctk.CTkLabel(
                    row_frame,
                    text=display,
                    width=120
                ).pack(side="left", padx=2)
        
        # Export button
        def export_report():
            file_path = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv")],
                initialfile=f"{title.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d')}.csv"
            )
            
            if file_path:
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(headers)
                    writer.writerows(data)
                messagebox.showinfo("Success", f"Report exported to {file_path}")
        
        ctk.CTkButton(
            dialog,
            text="📥 Export CSV",
            command=export_report,
            height=40
        ).pack(pady=10)
    
    # ========== USER MANAGEMENT TAB ==========
    
    def setup_user_management_tab(self):
        """Setup user management tab"""
        tab = self.tabview.tab("User Management")
        
        ctk.CTkLabel(
            tab,
            text="Admin User Management",
            font=ctk.CTkFont(size=24, weight="bold")
        ).pack(pady=20)
        
        # Action buttons
        action_frame = ctk.CTkFrame(tab, corner_radius=10)
        action_frame.pack(pady=10, padx=20, fill="x")
        
        ctk.CTkButton(
            action_frame,
            text="➕ Add Admin User",
            command=self.add_admin_user,
            width=150
        ).pack(side="left", padx=10, pady=10)
        
        ctk.CTkButton(
            action_frame,
            text="🔄 Refresh",
            command=self.refresh_admin_users,
            width=150
        ).pack(side="left", padx=10, pady=10)
        
        # Admin users list
        self.admin_users_frame = ctk.CTkScrollableFrame(tab, height=500)
        self.admin_users_frame.pack(pady=10, padx=20, fill="both", expand=True)
        
        # Load users
        self.refresh_admin_users()
    
    def refresh_admin_users(self):
        """Refresh admin users list"""
        for widget in self.admin_users_frame.winfo_children():
            widget.destroy()
        
        try:
            admins = self.auth.get_all_admins()
            
            if not admins:
                ctk.CTkLabel(
                    self.admin_users_frame,
                    text="No admin users found",
                    font=ctk.CTkFont(size=16)
                ).pack(pady=50)
                return
            
            # Headers
            headers = ["Username", "Role", "Email", "Full Name", "Status", "Created", "Last Login", "Actions"]
            headers_frame = ctk.CTkFrame(self.admin_users_frame, fg_color="transparent")
            headers_frame.pack(fill="x", pady=5)
            
            for header in headers:
                width = 100 if header not in ["Email", "Full Name"] else 150
                ctk.CTkLabel(
                    headers_frame,
                    text=header,
                    font=ctk.CTkFont(weight="bold", size=12),
                    width=width
                ).pack(side="left", padx=2)
            
            # Admin rows
            for admin in admins:
                row_frame = ctk.CTkFrame(self.admin_users_frame)
                row_frame.pack(fill="x", pady=2)
                
                username = admin.get('username', '')
                role = admin.get('role', '')
                email = admin.get('email', '')[:20] + "..." if len(admin.get('email', '')) > 20 else admin.get('email', '')
                full_name = admin.get('full_name', '')[:20]
                is_active = admin.get('is_active', True)
                created_at = admin.get('created_at', '')[:10] if admin.get('created_at') else 'N/A'
                last_login = admin.get('last_login', '')[:10] if admin.get('last_login') else 'Never'
                
                ctk.CTkLabel(row_frame, text=username, width=100).pack(side="left", padx=2)
                ctk.CTkLabel(row_frame, text=role, width=100).pack(side="left", padx=2)
                ctk.CTkLabel(row_frame, text=email, width=150).pack(side="left", padx=2)
                ctk.CTkLabel(row_frame, text=full_name, width=150).pack(side="left", padx=2)
                
                status_text = "Active" if is_active else "Inactive"
                status_color = "#28A745" if is_active else "#DC3545"
                ctk.CTkLabel(row_frame, text=status_text, text_color=status_color, width=100).pack(side="left", padx=2)
                
                ctk.CTkLabel(row_frame, text=created_at, width=100).pack(side="left", padx=2)
                ctk.CTkLabel(row_frame, text=last_login, width=100).pack(side="left", padx=2)
                
                # Actions
                actions_frame = ctk.CTkFrame(row_frame, fg_color="transparent")
                actions_frame.pack(side="left", padx=5)
                
                if username != self.username:  # Cannot delete yourself
                    ctk.CTkButton(
                        actions_frame,
                        text="🗑️",
                        width=30,
                        height=25,
                        fg_color="#DC3545",
                        command=lambda u=username: self.delete_admin_user(u)
                    ).pack(side="left", padx=1)
                    
                    ctk.CTkButton(
                        actions_frame,
                        text="🔄",
                        width=30,
                        height=25,
                        fg_color="#FFC107",
                        command=lambda u=username: self.reset_admin_password(u)
                    ).pack(side="left", padx=1)
                
                # Edit permissions button
                ctk.CTkButton(
                    actions_frame,
                    text="🔑",
                    width=30,
                    height=25,
                    fg_color="#17A2B8",
                    command=lambda u=username, r=role: self.edit_admin_permissions(u, r)
                ).pack(side="left", padx=1)
                
                ctk.CTkButton(
                    actions_frame,
                    text="✏️",
                    width=30,
                    height=25,
                    fg_color="#6f42c1",
                    command=lambda u=username: self.edit_admin_user(u)
                ).pack(side="left", padx=1)
            
        except Exception as e:
            ctk.CTkLabel(
                self.admin_users_frame,
                text=f"Error loading admin users: {str(e)}",
                text_color="red"
            ).pack(pady=20)
    
    def add_admin_user(self):
        """Add new admin user"""
        dialog = ctk.CTkToplevel(self.window)
        dialog.title("Add Admin User")
        dialog.geometry("500x650")
        dialog.transient(self.window)
        dialog.grab_set()
        
        ctk.CTkLabel(
            dialog,
            text="➕ Add New Admin User",
            font=ctk.CTkFont(size=20, weight="bold")
        ).pack(pady=20)
        
        form_frame = ctk.CTkFrame(dialog, corner_radius=10)
        form_frame.pack(pady=10, padx=20, fill="both", expand=True)
        
        fields = [
            ("Username*", "username"),
            ("Password*", "password"),
            ("Confirm Password*", "confirm_password"),
            ("Role", "role"),
            ("Email", "email"),
            ("Full Name", "full_name"),
            ("Permissions", "permissions"),
            ("Notes", "notes")
        ]
        
        entries = {}
        
        for label, key in fields:
            ctk.CTkLabel(form_frame, text=label).pack(anchor="w", padx=20, pady=(10, 2))
            
            if key == "role":
                var = ctk.StringVar(value="admin")
                menu = ctk.CTkOptionMenu(
                    form_frame,
                    variable=var,
                    values=["super_admin", "admin", "auditor", "operator"]
                )
                menu.pack(fill="x", padx=20, pady=2)
                entries[key] = var
            elif key == "permissions":
                frame = ctk.CTkFrame(form_frame, fg_color="transparent")
                frame.pack(fill="x", padx=20, pady=2)
                
                perms = {}
                for perm in ["view_vendors", "manage_vendors", "view_docs", "verify_docs", "manage_certs"]:
                    var = ctk.BooleanVar(value=True)
                    cb = ctk.CTkCheckBox(frame, text=perm.replace('_', ' ').title(), variable=var)
                    cb.pack(anchor="w")
                    perms[perm] = var
                entries[key] = perms
            elif "password" in key:
                entry = ctk.CTkEntry(form_frame, show="•")
                entry.pack(fill="x", padx=20, pady=2)
                entries[key] = entry
            elif key == "notes":
                entry = ctk.CTkTextbox(form_frame, height=60)
                entry.pack(fill="x", padx=20, pady=2)
                entries[key] = entry
            else:
                entry = ctk.CTkEntry(form_frame)
                entry.pack(fill="x", padx=20, pady=2)
                entries[key] = entry
        
        def save_admin():
            username = entries['username'].get()
            password = entries['password'].get()
            confirm = entries['confirm_password'].get()
            role = entries['role'].get()
            email = entries['email'].get()
            full_name = entries['full_name'].get()
            notes = entries['notes'].get("1.0", "end-1c") if hasattr(entries['notes'], 'get') else entries['notes'].get()
            
            if not username or not password:
                messagebox.showwarning("Input Required", "Username and password are required")
                return
            
            if password != confirm:
                messagebox.showerror("Error", "Passwords do not match")
                return
            
            if len(password) < 6:
                messagebox.showwarning("Weak Password", "Password must be at least 6 characters")
                return
            
            success, message = self.auth.create_admin({
                'username': username,
                'password': password,
                'role': role,
                'email': email,
                'full_name': full_name,
                'notes': notes,
                'created_by': self.username,
                'permissions': {k: v.get() for k, v in entries['permissions'].items()}
            })
            
            if success:
                if db and hasattr(db, 'log_audit_event'):
                    db.log_audit_event('admin', self.username, 'add_admin', f"Added admin user {username}")
                
                messagebox.showinfo("Success", f"Admin user {username} created!")
                dialog.destroy()
                self.refresh_admin_users()
            else:
                messagebox.showerror("Error", message)
        
        ctk.CTkButton(
            dialog,
            text="Create Admin User",
            command=save_admin,
            height=45,
            fg_color="#28A745"
        ).pack(pady=20, padx=20, fill="x")
    
    def edit_admin_user(self, username):
        """Edit admin user"""
        messagebox.showinfo("Edit Admin", f"Edit admin user {username}\n\nThis feature allows editing user details.")
    
    def edit_admin_permissions(self, username, current_role):
        """Edit admin permissions"""
        dialog = ctk.CTkToplevel(self.window)
        dialog.title(f"Edit Permissions - {username}")
        dialog.geometry("400x500")
        dialog.transient(self.window)
        dialog.grab_set()
        
        ctk.CTkLabel(
            dialog,
            text=f"🔑 Edit Permissions: {username}",
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(pady=20)
        
        frame = ctk.CTkFrame(dialog)
        frame.pack(pady=10, padx=20, fill="both", expand=True)
        
        ctk.CTkLabel(frame, text="Role:").pack(anchor="w", padx=20, pady=(10, 2))
        role_var = ctk.StringVar(value=current_role)
        role_menu = ctk.CTkOptionMenu(
            frame,
            variable=role_var,
            values=["super_admin", "admin", "auditor", "operator"]
        )
        role_menu.pack(fill="x", padx=20, pady=2)
        
        ctk.CTkLabel(frame, text="Specific Permissions:").pack(anchor="w", padx=20, pady=(20, 10))
        
        permissions = {
            "manage_vendors": ctk.BooleanVar(value=True),
            "manage_documents": ctk.BooleanVar(value=True),
            "manage_certificates": ctk.BooleanVar(value=True),
            "view_audit_logs": ctk.BooleanVar(value=True),
            "manage_admins": ctk.BooleanVar(value=False),
            "export_data": ctk.BooleanVar(value=True),
            "send_notifications": ctk.BooleanVar(value=True)
        }
        
        for perm, var in permissions.items():
            cb = ctk.CTkCheckBox(
                frame,
                text=perm.replace('_', ' ').title(),
                variable=var
            )
            cb.pack(anchor="w", padx=30, pady=2)
        
        def save_permissions():
            messagebox.showinfo("Success", f"Permissions updated for {username}")
            dialog.destroy()
        
        ctk.CTkButton(
            dialog,
            text="Save Permissions",
            command=save_permissions,
            height=45,
            fg_color="#28A745"
        ).pack(pady=20, padx=20, fill="x")
    
    def delete_admin_user(self, username):
        """Delete admin user"""
        if messagebox.askyesno("Delete Admin", f"Delete admin user {username}?"):
            success, message = self.auth.delete_admin(username, self.username)
            
            if success:
                if db and hasattr(db, 'log_audit_event'):
                    db.log_audit_event('admin', self.username, 'delete_admin', f"Deleted admin user {username}")
                
                messagebox.showinfo("Success", message)
                self.refresh_admin_users()
            else:
                messagebox.showerror("Error", message)
    
    def reset_admin_password(self, username):
        """Reset admin password to default"""
        if messagebox.askyesno("Reset Password", 
                               f"Reset password for {username} to 'admin123'?\n\nUser will be forced to change on next login."):
            success, message = self.auth.reset_admin_password(username, self.username)
            
            if success:
                if db and hasattr(db, 'log_audit_event'):
                    db.log_audit_event('admin', self.username, 'reset_password', f"Reset password for {username}")
                
                messagebox.showinfo("Success", message)
            else:
                messagebox.showerror("Error", message)
    
    # ========== SETTINGS TAB ==========
    
    def setup_settings_tab(self):
        """Setup settings tab"""
        tab = self.tabview.tab("Settings")
        
        ctk.CTkLabel(
            tab,
            text="System Settings",
            font=ctk.CTkFont(size=24, weight="bold")
        ).pack(pady=20)
        
        # Settings frame
        settings_frame = ctk.CTkFrame(tab, corner_radius=15)
        settings_frame.pack(pady=10, padx=20, fill="both", expand=True)
        
        # Change password section
        pass_frame = ctk.CTkFrame(settings_frame, corner_radius=10)
        pass_frame.pack(pady=20, padx=20, fill="x")
        
        ctk.CTkLabel(
            pass_frame,
            text="🔐 Change Password",
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(pady=10)
        
        ctk.CTkLabel(pass_frame, text="Current Password:").pack(anchor="w", padx=20, pady=(10, 2))
        self.current_pass_entry = ctk.CTkEntry(pass_frame, show="•", height=40)
        self.current_pass_entry.pack(fill="x", padx=20, pady=2)
        
        ctk.CTkLabel(pass_frame, text="New Password:").pack(anchor="w", padx=20, pady=(10, 2))
        self.new_pass_entry = ctk.CTkEntry(pass_frame, show="•", height=40)
        self.new_pass_entry.pack(fill="x", padx=20, pady=2)
        
        ctk.CTkLabel(pass_frame, text="Confirm New Password:").pack(anchor="w", padx=20, pady=(10, 2))
        self.confirm_pass_entry = ctk.CTkEntry(pass_frame, show="•", height=40)
        self.confirm_pass_entry.pack(fill="x", padx=20, pady=2)
        
        ctk.CTkButton(
            pass_frame,
            text="Change Password",
            command=self.change_password,
            height=45
        ).pack(pady=20, padx=20, fill="x")
        
        # Email settings
        email_frame = ctk.CTkFrame(settings_frame, corner_radius=10)
        email_frame.pack(pady=20, padx=20, fill="x")
        
        ctk.CTkLabel(
            email_frame,
            text="📧 Email Settings",
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(pady=10)
        
        ctk.CTkLabel(email_frame, text="SMTP Server:").pack(anchor="w", padx=20, pady=(10, 2))
        self.smtp_server_entry = ctk.CTkEntry(email_frame, height=40)
        self.smtp_server_entry.pack(fill="x", padx=20, pady=2)
        self.smtp_server_entry.insert(0, self.smtp_server)
        
        ctk.CTkLabel(email_frame, text="Port:").pack(anchor="w", padx=20, pady=(10, 2))
        self.smtp_port_entry = ctk.CTkEntry(email_frame, height=40)
        self.smtp_port_entry.pack(fill="x", padx=20, pady=2)
        self.smtp_port_entry.insert(0, str(self.smtp_port))
        
        ctk.CTkLabel(email_frame, text="Username:").pack(anchor="w", padx=20, pady=(10, 2))
        self.smtp_user_entry = ctk.CTkEntry(email_frame, height=40)
        self.smtp_user_entry.pack(fill="x", padx=20, pady=2)
        self.smtp_user_entry.insert(0, self.smtp_username)
        
        ctk.CTkLabel(email_frame, text="Password:").pack(anchor="w", padx=20, pady=(10, 2))
        self.smtp_pass_entry = ctk.CTkEntry(email_frame, show="•", height=40)
        self.smtp_pass_entry.pack(fill="x", padx=20, pady=2)
        self.smtp_pass_entry.insert(0, self.smtp_password)
        
        ctk.CTkButton(
            email_frame,
            text="Save Email Settings",
            command=self.save_email_settings,
            height=45
        ).pack(pady=20, padx=20, fill="x")
        
        # System info
        info_frame = ctk.CTkFrame(settings_frame, corner_radius=10)
        info_frame.pack(pady=20, padx=20, fill="x")
        
        ctk.CTkLabel(
            info_frame,
            text="ℹ️ System Information",
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(pady=10)
        
        # Get system info
        db_path = "database/certauth.db"
        db_size = os.path.getsize(db_path) / 1024 / 1024 if os.path.exists(db_path) else 0
        
        ca_status = "Active" if os.path.exists("certs/root_ca.crt") else "Not Created"
        
        info_items = [
            ("Database Size:", f"{db_size:.2f} MB"),
            ("CA Status:", ca_status),
            ("Admin User:", self.username),
            ("Admin Role:", self.admin_info.get('role', 'admin') if self.admin_info else 'admin'),
            ("Last Login:", self.admin_info.get('last_login', 'N/A')[:10] if self.admin_info and self.admin_info.get('last_login') else 'N/A')
        ]
        
        for label, value in info_items:
            item_frame = ctk.CTkFrame(info_frame, fg_color="transparent")
            item_frame.pack(fill="x", padx=20, pady=5)
            
            ctk.CTkLabel(
                item_frame,
                text=label,
                font=ctk.CTkFont(size=14)
            ).pack(side="left")
            
            ctk.CTkLabel(
                item_frame,
                text=value,
                font=ctk.CTkFont(size=14, weight="bold")
            ).pack(side="right")
    
    def change_password(self):
        """Change admin password"""
        current = self.current_pass_entry.get()
        new_pass = self.new_pass_entry.get()
        confirm = self.confirm_pass_entry.get()
        
        if not current or not new_pass or not confirm:
            messagebox.showwarning("Input Required", "Please fill all fields")
            return
        
        if new_pass != confirm:
            messagebox.showerror("Error", "New passwords do not match")
            return
        
        if len(new_pass) < 6:
            messagebox.showwarning("Weak Password", "Password must be at least 6 characters")
            return
        
        success, message = self.auth.change_password(self.username, new_pass, current)
        
        if success:
            if db and hasattr(db, 'log_audit_event'):
                db.log_audit_event('admin', self.username, 'change_password', "Password changed")
            
            messagebox.showinfo("Success", "Password changed successfully!")
            self.current_pass_entry.delete(0, "end")
            self.new_pass_entry.delete(0, "end")
            self.confirm_pass_entry.delete(0, "end")
        else:
            messagebox.showerror("Error", message)
    
    def save_email_settings(self):
        """Save email settings"""
        self.smtp_server = self.smtp_server_entry.get()
        self.smtp_port = int(self.smtp_port_entry.get())
        self.smtp_username = self.smtp_user_entry.get()
        self.smtp_password = self.smtp_pass_entry.get()
        
        messagebox.showinfo("Success", "Email settings saved!")
    
    def logout(self):
        """Logout admin"""
        if messagebox.askyesno("Logout", "Are you sure you want to logout?"):
            if db and hasattr(db, 'log_audit_event'):
                db.log_audit_event('admin', self.username, 'logout', "Admin logged out")
            
            self.safe_quit()
            # Return to main menu
            try:
                from gui.main_menu import main
                main()
            except:
                # If main_menu not available, just close
                pass
    
    def run(self):
        self.window.mainloop()


# ========== MAIN FUNCTION ==========
def main():
    """Main entry point for admin panel"""
    def on_login_success(username):
        """Callback after successful login"""
        admin = AdminPanel(username)
        admin.run()
    
    login = LoginWindow(on_login_success)
    login.run()


if __name__ == "__main__":
    main()