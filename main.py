"""
MAIN ENTRY POINT - VENDOR AUTHENTICATION PKI SYSTEM
ST6051CEM - Cryptography Coursework
"""
import sys
import os

# Add current directory to path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

def main():
    """Launch the GUI main menu"""
    try:
        # First check if GUI main menu exists
        try:
            from gui.main_menu import MainMenu
            print("="*70)
            print("🔐 LAUNCHING VENDOR AUTHENTICATION PKI SYSTEM")
            print("="*70)
            print("ST6051CEM - Practical Cryptography Coursework")
            print("Coursework Requirements:")
            print("1. PKI-based User Authentication ✓")
            print("2. Document Signing/Verification ✓")
            print("3. Security Features ✓")
            print("4. Key Management ✓")
            print("="*70)
            print("Starting GUI Main Menu...")
            app = MainMenu()
            app.run()
        except ImportError as e:
            print(f"⚠️ GUI Main Menu not found: {e}")
            print("Falling back to Admin Panel...")
            
            # Try to import admin panel's main function
            try:
                from gui.admin_panel import main as admin_main
                admin_main()
            except ImportError as e2:
                print(f"❌ Cannot load admin portal: {e2}")
                print("\nTrying direct admin panel import...")
                
                # Fallback: import the class directly
                from gui.admin_panel import AdminPanel, LoginWindow
                
                def run_admin():
                    def on_login_success(username):
                        admin = AdminPanel(username)
                        admin.run()
                    
                    login = LoginWindow(on_login_success)
                    login.run()
                
                run_admin()
    
    except ImportError as e:
        print(f"❌ Error: {e}")
        print("\n🔧 Please install required packages:")
        print("pip install customtkinter cryptography")
        input("\nPress Enter to exit...")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()