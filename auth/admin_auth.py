"""
Admin authentication system with database integration
"""
import hashlib
import sqlite3
from datetime import datetime

class AdminAuth:
    def __init__(self):
        self.db_path = "database/certauth.db"
        self.setup_admin_table()
        self.setup_default_admin()
    
    def setup_admin_table(self):
        """Create admin table if not exists"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'admin',
            email TEXT,
            full_name TEXT,
            is_active BOOLEAN DEFAULT TRUE,
            first_login BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            login_attempts INTEGER DEFAULT 0,
            locked_until TIMESTAMP,
            created_by TEXT,
            notes TEXT
        )
        ''')
        
        conn.commit()
        conn.close()
    
    def setup_default_admin(self):
        """Create default admin if no admins exist"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM admins")
        count = cursor.fetchone()[0]
        
        if count == 0:
            # Create default admin
            password_hash = self.hash_password("admin123")
            cursor.execute('''
            INSERT INTO admins (username, password_hash, role, email, full_name, first_login)
            VALUES (?, ?, ?, ?, ?, ?)
            ''', ("admin", password_hash, "super_admin", "admin@CertAuth-pki.com", 
                  "System Administrator", True))
            conn.commit()
        
        conn.close()
    
    def hash_password(self, password):
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def authenticate(self, username, password):
        """Authenticate admin user"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT * FROM admins 
        WHERE username = ? AND is_active = TRUE
        ''', (username,))
        
        admin = cursor.fetchone()
        
        if not admin:
            conn.close()
            return False, "Invalid username or password"
        
        # Verify password
        input_hash = self.hash_password(password)
        if admin[2] != input_hash:  # password_hash is at index 2
            conn.close()
            return False, "Invalid username or password"
        
        # Update last login
        cursor.execute('''
        UPDATE admins 
        SET last_login = ?
        WHERE username = ?
        ''', (datetime.now().isoformat(), username))
        
        conn.commit()
        conn.close()
        
        # Check if first login
        if admin[7]:  # first_login is at index 7
            return True, "first_login"
        
        return True, "authenticated"
    
    def change_password(self, username, new_password, old_password=None):
        """Change admin password"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM admins WHERE username = ?", (username,))
        admin = cursor.fetchone()
        
        if not admin:
            conn.close()
            return False, "Admin not found"
        
        # If old password provided, verify it
        if old_password:
            old_hash = self.hash_password(old_password)
            if admin[2] != old_hash:
                conn.close()
                return False, "Current password is incorrect"
        
        # Update password
        new_hash = self.hash_password(new_password)
        cursor.execute('''
        UPDATE admins 
        SET password_hash = ?, first_login = FALSE
        WHERE username = ?
        ''', (new_hash, username))
        
        conn.commit()
        conn.close()
        
        return True, "Password changed successfully"
    
    def create_admin(self, admin_data):
        """Create new admin user"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
            INSERT INTO admins 
            (username, password_hash, role, email, full_name, created_by, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                admin_data['username'],
                self.hash_password(admin_data['password']),
                admin_data.get('role', 'admin'),
                admin_data.get('email', ''),
                admin_data.get('full_name', ''),
                admin_data.get('created_by', 'system'),
                admin_data.get('notes', '')
            ))
            
            conn.commit()
            conn.close()
            return True, "Admin created successfully"
            
        except sqlite3.IntegrityError:
            conn.close()
            return False, "Username already exists"
        except Exception as e:
            conn.close()
            return False, f"Error creating admin: {str(e)}"
    
    def get_all_admins(self):
        """Get all admin users"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT username, role, email, full_name, is_active, 
               created_at, last_login, first_login, notes
        FROM admins
        ORDER BY created_at DESC
        ''')
        
        admins = cursor.fetchall()
        conn.close()
        
        result = []
        for admin in admins:
            result.append({
                'username': admin[0],
                'role': admin[1],
                'email': admin[2],
                'full_name': admin[3],
                'is_active': admin[4],
                'created_at': admin[5],
                'last_login': admin[6],
                'first_login': admin[7],
                'notes': admin[8]
            })
        
        return result
    
    def delete_admin(self, username, deleted_by=None):
        """Delete admin user (soft delete)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        UPDATE admins 
        SET is_active = FALSE, notes = ?
        WHERE username = ? AND username != 'admin'
        ''', (f"Deleted by {deleted_by} on {datetime.now().isoformat()}", username))
        
        affected = cursor.rowcount
        conn.commit()
        conn.close()
        
        if affected > 0:
            return True, f"Admin {username} deleted"
        else:
            return False, "Cannot delete super admin or user not found"
    
    def reset_admin_password(self, username, reset_by=None):
        """Reset admin password to default"""
        default_hash = self.hash_password("admin123")
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        UPDATE admins 
        SET password_hash = ?, first_login = TRUE, notes = ?
        WHERE username = ?
        ''', (default_hash, f"Password reset by {reset_by} on {datetime.now().isoformat()}", username))
        
        affected = cursor.rowcount
        conn.commit()
        conn.close()
        
        if affected > 0:
            return True, f"Password reset for {username} to 'admin123'"
        else:
            return False, "User not found"
    
    def get_admin_info(self, username):
        """Get admin information"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT username, role, email, full_name, first_login, last_login
        FROM admins WHERE username = ?
        ''', (username,))
        
        admin = cursor.fetchone()
        conn.close()
        
        if admin:
            return {
                'username': admin[0],
                'role': admin[1],
                'email': admin[2],
                'full_name': admin[3],
                'first_login': admin[4],
                'last_login': admin[5]
            }
        return None