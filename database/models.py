# database/models.py
"""
Database schema for CertAuth: Vendor Authentication System
"""
import sqlite3
import json
from datetime import datetime
import os
import random
import time

class DatabaseManager:
    def __init__(self, db_path="database/certauth.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database with required tables"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # VENDORS table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS vendors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vendor_id TEXT UNIQUE NOT NULL,
            company_name TEXT NOT NULL,
            contact_email TEXT NOT NULL,
            contact_person TEXT,
            registration_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'pending',  -- pending, active, suspended, revoked
            public_key TEXT,
            certificate_serial TEXT,
            last_login TIMESTAMP
        )
        ''')
        
        # CERTIFICATES table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            serial_number TEXT UNIQUE NOT NULL,
            vendor_id TEXT NOT NULL,
            issuer_ca TEXT NOT NULL,
            subject TEXT NOT NULL,
            not_valid_before TIMESTAMP NOT NULL,
            not_valid_after TIMESTAMP NOT NULL,
            revoked BOOLEAN DEFAULT FALSE,
            revocation_reason TEXT,
            revocation_date TIMESTAMP,
            certificate_data TEXT NOT NULL,
            FOREIGN KEY (vendor_id) REFERENCES vendors(vendor_id)
        )
        ''')
        
        # SIGNED_DOCUMENTS table (Quality Certificates)
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS signed_documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_id TEXT UNIQUE NOT NULL,
            vendor_id TEXT NOT NULL,
            document_type TEXT NOT NULL,  -- quality_cert, delivery_note, compliance_cert
            document_title TEXT NOT NULL,
            document_hash TEXT NOT NULL,
            digital_signature TEXT NOT NULL,
            signing_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            verification_status TEXT DEFAULT 'pending',  -- pending, verified, rejected
            verified_by TEXT,
            verification_timestamp TIMESTAMP,
            metadata TEXT,  -- JSON with additional data
            FOREIGN KEY (vendor_id) REFERENCES vendors(vendor_id)
        )
        ''')
        
        # ========== NEW TABLES FOR FILE SHARING ==========
        
        # SHARED_DOCUMENTS table (for encrypted file sharing)
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS shared_documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            share_id TEXT UNIQUE NOT NULL,
            sender_id TEXT NOT NULL,
            recipient_id TEXT NOT NULL,
            encrypted_data TEXT NOT NULL,  -- JSON string of encrypted document
            file_name TEXT,
            file_size INTEGER,
            share_message TEXT,
            shared_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_read BOOLEAN DEFAULT FALSE,
            expires_at TIMESTAMP,
            decrypted_file_path TEXT,
            FOREIGN KEY (sender_id) REFERENCES vendors(vendor_id),
            FOREIGN KEY (recipient_id) REFERENCES vendors(vendor_id)
        )
        ''')
        
        # SECURE_MESSAGES table (for encrypted vendor-to-vendor communication)
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS secure_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id TEXT UNIQUE NOT NULL,
            sender_id TEXT NOT NULL,
            recipient_id TEXT NOT NULL,
            subject TEXT NOT NULL,
            encrypted_content TEXT NOT NULL,
            sent_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_read BOOLEAN DEFAULT FALSE,
            decrypted_content TEXT,
            FOREIGN KEY (sender_id) REFERENCES vendors(vendor_id),
            FOREIGN KEY (recipient_id) REFERENCES vendors(vendor_id)
        )
        ''')
        
        # ========== END NEW TABLES ==========
        
        # AUDIT_LOG table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_type TEXT NOT NULL,  -- admin, vendor
            user_id TEXT NOT NULL,
            action TEXT NOT NULL,  -- login, logout, sign_document, verify_document, issue_cert, revoke_cert
            details TEXT,
            ip_address TEXT,
            success BOOLEAN
        )
        ''')
        
        # CERTIFICATE_REVOCATION_LIST (CRL)
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS crl (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            serial_number TEXT UNIQUE NOT NULL,
            revocation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            reason_code INTEGER,  -- 0=unspecified, 1=keyCompromise, 2=CACompromise, 3=affiliationChanged, 4=superseded, 5=cessationOfOperation, 6=certificateHold
            reason_text TEXT
        )
        ''')
        
        conn.commit()
        conn.close()
        print("✅ Database initialized with manufacturing supply chain schema (WITH FILE SHARING)")
    
    # ===== VENDOR OPERATIONS =====
    def register_vendor(self, vendor_data):
        """Register a new vendor/supplier with unique vendor_id"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Generate unique vendor ID using timestamp and random number
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        random_suffix = random.randint(1000, 9999)
        vendor_id = f"VEND{timestamp}{random_suffix}"
        
        # Ensure uniqueness (retry if needed)
        attempts = 0
        while attempts < 5:
            cursor.execute("SELECT COUNT(*) FROM vendors WHERE vendor_id = ?", (vendor_id,))
            if cursor.fetchone()[0] == 0:
                break
            # If duplicate, generate new ID
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            random_suffix = random.randint(1000, 9999)
            vendor_id = f"VEND{timestamp}{random_suffix}"
            attempts += 1
        
        if attempts >= 5:
            # Fallback: use milliseconds since epoch
            vendor_id = f"VEND{int(time.time() * 1000)}"
        
        cursor.execute('''
        INSERT INTO vendors (vendor_id, company_name, contact_email, contact_person, status)
        VALUES (?, ?, ?, ?, ?)
        ''', (
            vendor_id,
            vendor_data['company_name'],
            vendor_data['email'],
            vendor_data.get('contact_person', ''),
            'pending'
        ))
        
        conn.commit()
        conn.close()
        
        print(f"✅ Vendor registered: {vendor_id} - {vendor_data['company_name']}")
        return vendor_id
    
    def update_vendor_certificate(self, vendor_id, public_key, certificate_serial):
        """Update vendor with public key and certificate info"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        UPDATE vendors 
        SET public_key = ?, certificate_serial = ?, status = 'active'
        WHERE vendor_id = ?
        ''', (public_key, certificate_serial, vendor_id))
        
        conn.commit()
        conn.close()
        print(f"✅ Updated vendor certificate: {vendor_id}")
    
    def get_vendor_by_id(self, vendor_id):
        """Get vendor details"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM vendors WHERE vendor_id = ?', (vendor_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            columns = [desc[0] for desc in cursor.description]
            return dict(zip(columns, row))
        return None
    
    def get_all_vendors(self, status=None):
        """Get all vendors (optionally filtered by status)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if status:
            cursor.execute('SELECT * FROM vendors WHERE status = ? ORDER BY company_name', (status,))
        else:
            cursor.execute('SELECT * FROM vendors ORDER BY company_name')
        
        rows = cursor.fetchall()
        conn.close()
        
        if rows:
            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, row)) for row in rows]
        return []
    
    # ===== CERTIFICATE OPERATIONS =====
    def store_certificate(self, cert_data):
        """Store issued certificate"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        INSERT INTO certificates (serial_number, vendor_id, issuer_ca, subject, 
                                 not_valid_before, not_valid_after, certificate_data)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            cert_data['serial'],
            cert_data['vendor_id'],
            cert_data['issuer'],
            cert_data['subject'],
            cert_data['not_valid_before'],
            cert_data['not_valid_after'],
            cert_data['certificate_data']
        ))
        
        conn.commit()
        conn.close()
        print(f"✅ Certificate stored: {cert_data['serial']}")
    
    def revoke_certificate(self, serial_number, reason_code=0, reason_text=""):
        """Revoke a certificate"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Update certificates table
        cursor.execute('''
        UPDATE certificates 
        SET revoked = TRUE, revocation_reason = ?, revocation_date = CURRENT_TIMESTAMP
        WHERE serial_number = ?
        ''', (reason_text, serial_number))
        
        # Add to CRL
        cursor.execute('''
        INSERT INTO crl (serial_number, reason_code, reason_text)
        VALUES (?, ?, ?)
        ''', (serial_number, reason_code, reason_text))
        
        # Update vendor status
        cursor.execute('''
        UPDATE vendors 
        SET status = 'revoked'
        WHERE certificate_serial = ?
        ''', (serial_number,))
        
        conn.commit()
        conn.close()
        print(f"⚠️ Certificate revoked: {serial_number}")
    
    def is_certificate_revoked(self, serial_number):
        """Check if certificate is revoked"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM crl WHERE serial_number = ?', (serial_number,))
        result = cursor.fetchone() is not None
        conn.close()
        return result
    
    # ===== DOCUMENT OPERATIONS =====
    def store_signed_document(self, doc_data):
        """Store a signed quality document"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        metadata_json = json.dumps(doc_data.get('metadata', {}))
        
        # Check if document_content column exists
        cursor.execute("PRAGMA table_info(signed_documents)")
        columns = [col[1] for col in cursor.fetchall()]
        
        if 'document_content' in columns:
            # New schema with content column
            cursor.execute('''
            INSERT INTO signed_documents 
            (document_id, vendor_id, document_type, document_title, document_content,
            document_hash, digital_signature, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                doc_data['document_id'],
                doc_data['vendor_id'],
                doc_data['document_type'],
                doc_data['title'],
                doc_data.get('content', ''),  # ← This stores the actual document content
                doc_data['hash'],
                doc_data['signature'],
                metadata_json
            ))
        else:
            # Old schema without content column
            cursor.execute('''
            INSERT INTO signed_documents 
            (document_id, vendor_id, document_type, document_title, 
            document_hash, digital_signature, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                doc_data['document_id'],
                doc_data['vendor_id'],
                doc_data['document_type'],
                doc_data['title'],
                doc_data['hash'],
                doc_data['signature'],
                metadata_json
            ))
        
        conn.commit()
        conn.close()
        print(f"✅ Document stored: {doc_data['document_id']}")
    
    def update_document_verification(self, document_id, status, verified_by):
        """Update document verification status"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        UPDATE signed_documents 
        SET verification_status = ?, verified_by = ?, verification_timestamp = CURRENT_TIMESTAMP
        WHERE document_id = ?
        ''', (status, verified_by, document_id))
        
        conn.commit()
        conn.close()
        print(f"✅ Document verified: {document_id} - {status}")
    
    def get_documents_by_vendor(self, vendor_id, doc_type=None):
        """Get all documents for a vendor"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if doc_type:
            cursor.execute('''
            SELECT * FROM signed_documents 
            WHERE vendor_id = ? AND document_type = ?
            ORDER BY signing_timestamp DESC
            ''', (vendor_id, doc_type))
        else:
            cursor.execute('''
            SELECT * FROM signed_documents 
            WHERE vendor_id = ? 
            ORDER BY signing_timestamp DESC
            ''', (vendor_id,))
        
        rows = cursor.fetchall()
        conn.close()
        
        if rows:
            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, row)) for row in rows]
        return []
    
    # ====== NEW: FILE SHARING OPERATIONS ======
    
    def share_document(self, share_data):
        """Share an encrypted document with another vendor"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Generate unique share ID
        share_id = f"SHARE{datetime.now().strftime('%Y%m%d%H%M%S')}{random.randint(1000, 9999)}"
        
        # Convert encrypted data to JSON string
        encrypted_data_json = json.dumps(share_data['encrypted_data'])
        
        # Set expiration (30 days from now)
        expires_at = datetime.now().timestamp() + (30 * 24 * 60 * 60)
        expires_at_str = datetime.fromtimestamp(expires_at).isoformat()
        
        cursor.execute('''
        INSERT INTO shared_documents 
        (share_id, sender_id, recipient_id, encrypted_data, file_name, 
         file_size, share_message, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            share_id,
            share_data['sender_id'],
            share_data['recipient_id'],
            encrypted_data_json,
            share_data.get('file_name', 'encrypted_document.json'),
            share_data.get('file_size', len(encrypted_data_json)),
            share_data.get('message', ''),
            expires_at_str
        ))
        
        conn.commit()
        conn.close()
        
        print(f"✅ Document shared: {share_id} from {share_data['sender_id']} to {share_data['recipient_id']}")
        return share_id
    
    def get_shared_documents_for_vendor(self, vendor_id, unread_only=False):
        """Get all documents shared with a vendor"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if unread_only:
            cursor.execute('''
            SELECT * FROM shared_documents 
            WHERE recipient_id = ? AND is_read = FALSE
            ORDER BY shared_timestamp DESC
            ''', (vendor_id,))
        else:
            cursor.execute('''
            SELECT * FROM shared_documents 
            WHERE recipient_id = ?
            ORDER BY shared_timestamp DESC
            ''', (vendor_id,))
        
        rows = cursor.fetchall()
        conn.close()
        
        if rows:
            columns = [desc[0] for desc in cursor.description]
            shared_docs = []
            for row in rows:
                doc = dict(zip(columns, row))
                # Parse encrypted data JSON
                try:
                    doc['encrypted_data'] = json.loads(doc['encrypted_data'])
                except:
                    doc['encrypted_data'] = {}
                shared_docs.append(doc)
            return shared_docs
        return []
    
    def get_sent_documents_by_vendor(self, vendor_id):
        """Get all documents sent by a vendor"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT * FROM shared_documents 
        WHERE sender_id = ?
        ORDER BY shared_timestamp DESC
        ''', (vendor_id,))
        
        rows = cursor.fetchall()
        conn.close()
        
        if rows:
            columns = [desc[0] for desc in cursor.description]
            sent_docs = []
            for row in rows:
                doc = dict(zip(columns, row))
                try:
                    doc['encrypted_data'] = json.loads(doc['encrypted_data'])
                except:
                    doc['encrypted_data'] = {}
                sent_docs.append(doc)
            return sent_docs
        return []
    
    def mark_shared_document_as_read(self, share_id):
        """Mark a shared document as read"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        UPDATE shared_documents 
        SET is_read = TRUE 
        WHERE share_id = ?
        ''', (share_id,))
        
        conn.commit()
        conn.close()
        print(f"✅ Document marked as read: {share_id}")
    
    def delete_shared_document(self, share_id):
        """Delete a shared document (by sender or expired)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM shared_documents WHERE share_id = ?', (share_id,))
        
        conn.commit()
        conn.close()
        print(f"🗑️ Document deleted: {share_id}")
    
    def store_secure_message(self, message_data):
        """Store a secure message in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        INSERT INTO secure_messages 
        (message_id, sender_id, recipient_id, subject, encrypted_content, sent_timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            message_data['message_id'],
            message_data['sender_id'],
            message_data['recipient_id'],
            message_data['subject'],
            message_data['encrypted_content'],
            message_data.get('sent_timestamp', datetime.now().isoformat())
        ))
        
        conn.commit()
        conn.close()
        print(f"✅ Secure message stored: {message_data['message_id']}")
    
    def get_received_messages(self, vendor_id, unread_only=False):
        """Get messages received by a vendor"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if unread_only:
            cursor.execute('''
            SELECT * FROM secure_messages 
            WHERE recipient_id = ? AND is_read = FALSE
            ORDER BY sent_timestamp DESC
            ''', (vendor_id,))
        else:
            cursor.execute('''
            SELECT * FROM secure_messages 
            WHERE recipient_id = ?
            ORDER BY sent_timestamp DESC
            ''', (vendor_id,))
        
        rows = cursor.fetchall()
        conn.close()
        
        if rows:
            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, row)) for row in rows]
        return []
    
    def mark_message_as_read(self, message_id, decrypted_content=None):
        """Mark a message as read and optionally store decrypted content"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if decrypted_content:
            cursor.execute('''
            UPDATE secure_messages 
            SET is_read = TRUE, decrypted_content = ?
            WHERE message_id = ?
            ''', (decrypted_content, message_id))
        else:
            cursor.execute('''
            UPDATE secure_messages 
            SET is_read = TRUE 
            WHERE message_id = ?
            ''', (message_id,))
        
        conn.commit()
        conn.close()
        print(f"✅ Message marked as read: {message_id}")
    
    # ===== AUDIT LOGGING =====
    def log_audit_event(self, user_type, user_id, action, details="", ip="", success=True):
        """Log an audit event"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        INSERT INTO audit_log (user_type, user_id, action, details, ip_address, success)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_type, user_id, action, details, ip, success))
        
        conn.commit()
        conn.close()
        print(f"📝 Audit logged: {user_type}/{user_id} - {action}")
    
    def get_audit_logs(self, limit=100):
        """Get recent audit logs"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
        SELECT * FROM audit_log 
        ORDER BY timestamp DESC 
        LIMIT ?
        ''', (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        if rows:
            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, row)) for row in rows]
        return []
    
    # ===== STATISTICS =====
    def get_system_stats(self):
        """Get system statistics for dashboard"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        stats = {}
        
        # Vendor counts
        cursor.execute("SELECT status, COUNT(*) FROM vendors GROUP BY status")
        vendor_stats = cursor.fetchall()
        stats['vendors'] = {status: count for status, count in vendor_stats}
        stats['total_vendors'] = sum(count for _, count in vendor_stats)
        
        # Certificate counts
        cursor.execute("SELECT revoked, COUNT(*) FROM certificates GROUP BY revoked")
        cert_stats = cursor.fetchall()
        stats['certificates'] = {'active': 0, 'revoked': 0}
        for revoked, count in cert_stats:
            if revoked:
                stats['certificates']['revoked'] = count
            else:
                stats['certificates']['active'] = count
        
        # Document counts
        cursor.execute("SELECT verification_status, COUNT(*) FROM signed_documents GROUP BY verification_status")
        doc_stats = cursor.fetchall()
        stats['documents'] = {status: count for status, count in doc_stats}
        stats['total_documents'] = sum(count for _, count in doc_stats)
        
        # Shared documents count
        cursor.execute("SELECT COUNT(*) FROM shared_documents")
        stats['shared_documents'] = cursor.fetchone()[0]
        
        # Secure messages count
        cursor.execute("SELECT COUNT(*) FROM secure_messages")
        stats['secure_messages'] = cursor.fetchone()[0]
        
        # Recent activity
        cursor.execute("SELECT COUNT(*) FROM audit_log WHERE timestamp > datetime('now', '-1 day')")
        stats['recent_activity'] = cursor.fetchone()[0]
        
        conn.close()
        return stats
    
    # ===== CLEANUP/DEBUG =====
    def clear_test_data(self):
        """Clear all test data (for debugging)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        tables = ['vendors', 'certificates', 'signed_documents', 'shared_documents', 
                 'secure_messages', 'audit_log', 'crl']
        for table in tables:
            cursor.execute(f"DELETE FROM {table}")
        
        conn.commit()
        conn.close()
        print("🧹 All test data cleared")
    
    def reset_database(self):
        """Reset entire database (drop all tables and recreate)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        tables = ['vendors', 'certificates', 'signed_documents', 'shared_documents',
                 'secure_messages', 'audit_log', 'crl']
        for table in tables:
            cursor.execute(f"DROP TABLE IF EXISTS {table}")
        
        conn.commit()
        conn.close()
        
        # Recreate tables
        self.init_database()
        print("🔄 Database completely reset")

# Singleton instance
db = DatabaseManager()

if __name__ == "__main__":
    # Test database initialization
    db.init_database()
    print("✅ Database ready for manufacturing supply chain PKI system (WITH FILE SHARING)")
    
    # Test vendor registration
    test_vendor = {
        'company_name': 'Test Steel Company',
        'email': 'test@steelcompany.com',
        'contact_person': 'John Doe'
    }
    
    vendor_id = db.register_vendor(test_vendor)
    print(f"✅ Test vendor registered: {vendor_id}")
    
    # Test file sharing methods
    test_share_data = {
        'sender_id': 'TEST_SENDER',
        'recipient_id': 'TEST_RECIPIENT',
        'encrypted_data': {'test': 'encrypted data'},
        'message': 'Test share'
    }
    
    share_id = db.share_document(test_share_data)
    print(f"✅ Test document shared: {share_id}")