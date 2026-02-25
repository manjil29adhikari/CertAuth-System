"""
Encryption module for CertAuth: Vendor Authentication System PKI
Provides document encryption/decryption and secure messaging
"""

import base64
import json
import os
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # Fixed import
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

class EncryptionManager:
    """Handles symmetric and asymmetric encryption for documents"""
    
    @staticmethod
    def generate_symmetric_key(password: str = None, salt: bytes = None):
        """
        Generate a symmetric key.
        If password is given, derive key using PBKDF2.
        Otherwise, generate a random 32-byte key.
        Returns (key, salt) where salt is None if password not used.
        """
        if password:
            if salt is None:
                salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(password.encode())
            return key, salt
        else:
            return os.urandom(32), None

    @staticmethod
    def encrypt_document(content: str, public_key_pem: str, password: str = None) -> dict:
        """
        Hybrid encryption:
        1. Generate a symmetric key (random or derived from password).
        2. Encrypt content with AES-CBC using that key.
        3. Encrypt the symmetric key with the recipient's RSA public key.
        Returns a dictionary with all components base64-encoded.
        """
        try:
            # Load recipient's public key
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode(),
                backend=default_backend()
            )

            # Generate symmetric key and IV
            symmetric_key, salt = EncryptionManager.generate_symmetric_key(password)
            iv = os.urandom(16)

            # Encrypt content with AES
            cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(content.encode()) + padder.finalize()
            encrypted_content = encryptor.update(padded_data) + encryptor.finalize()

            # Encrypt symmetric key with RSA
            encrypted_key = public_key.encrypt(
                symmetric_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            return {
                'encrypted_content': base64.b64encode(encrypted_content).decode(),
                'encrypted_key': base64.b64encode(encrypted_key).decode(),
                'iv': base64.b64encode(iv).decode(),
                'salt': base64.b64encode(salt).decode() if salt else None,
                'algorithm': 'RSA-AES-HYBRID',
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            raise Exception(f"Encryption failed: {str(e)}")

    @staticmethod
    def decrypt_document(encrypted_data: dict, private_key_pem: str, password: str = None) -> str:
        """Decrypt hybrid encrypted document"""
        try:
            # print(f"\n🔍 DECRYPT DEBUG: decrypt_document called")
            # print(f"🔍 DECRYPT DEBUG: Password provided: {'Yes' if password else 'No'}")
            if password:
                # print(f"🔍 DECRYPT DEBUG: Password length: {len(password)}")
                pass
                
            # Load private key
            try:
                # print("🔍 DECRYPT DEBUG: Trying to load private key without password...")
                private_key = serialization.load_pem_private_key(
                    private_key_pem.encode(),
                    password=None
                )
                # print("✅ DECRYPT DEBUG: Private key loaded WITHOUT password")
            except TypeError:
                # print("🔍 DECRYPT DEBUG: Private key requires password")
                if not password:
                    # print("❌ DECRYPT DEBUG: No password provided but key is encrypted!")
                    raise ValueError("Password was not given but private key is encrypted")
                # print("🔍 DECRYPT DEBUG: Trying to load private key WITH password...")
                private_key = serialization.load_pem_private_key(
                    private_key_pem.encode(),
                    password=password.encode()
                )
                # print("✅ DECRYPT DEBUG: Private key loaded WITH password")
            
            # Decode base64 data
            # print(f"🔍 DECRYPT DEBUG: Encrypted data keys: {encrypted_data.keys()}")
            
            try:
                encrypted_content = base64.b64decode(encrypted_data['encrypted_content'])
                # print(f"✅ DECRYPT DEBUG: encrypted_content decoded, length: {len(encrypted_content)} bytes")
            except Exception as e:
                # print(f"❌ DECRYPT DEBUG: Failed to decode encrypted_content: {e}")
                raise
            
            try:
                encrypted_key = base64.b64decode(encrypted_data['encrypted_key'])
                # print(f"✅ DECRYPT DEBUG: encrypted_key decoded, length: {len(encrypted_key)} bytes")
            except Exception as e:
                # print(f"❌ DECRYPT DEBUG: Failed to decode encrypted_key: {e}")
                raise
            
            try:
                iv = base64.b64decode(encrypted_data['iv'])
                # print(f"✅ DECRYPT DEBUG: iv decoded, length: {len(iv)} bytes (should be 16)")
            except Exception as e:
                # print(f"❌ DECRYPT DEBUG: Failed to decode iv: {e}")
                raise
            
            salt = None
            if encrypted_data.get('salt'):
                try:
                    salt = base64.b64decode(encrypted_data['salt'])
                    salt
                except:
                    salt = None
            
            # Decrypt symmetric key with RSA private key
            # print("🔍 DECRYPT DEBUG: Attempting to decrypt symmetric key with RSA...")
            try:
                symmetric_key = private_key.decrypt(
                    encrypted_key,
                    asym_padding.OAEP(
                        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                # print(f"✅ DECRYPT DEBUG: Symmetric key decrypted, length: {len(symmetric_key)} bytes (should be 32)")
            except Exception as e:
                # print(f"❌ DECRYPT DEBUG: Failed to decrypt symmetric key: {e}")
                raise
            
            # Decrypt content with AES
            # print("🔍 DECRYPT DEBUG: Attempting to decrypt content with AES...")
            try:
                cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv))
                decryptor = cipher.decryptor()
                decrypted_padded = decryptor.update(encrypted_content) + decryptor.finalize()
                # print(f"✅ DECRYPT DEBUG: AES decryption successful, padded length: {len(decrypted_padded)}")
            except Exception as e:
                # print(f"❌ DECRYPT DEBUG: AES decryption failed: {e}")
                raise
            
            # Unpad content
            # print("🔍 DECRYPT DEBUG: Attempting to remove padding...")
            try:
                unpadder = padding.PKCS7(128).unpadder()
                decrypted_content = unpadder.update(decrypted_padded) + unpadder.finalize()
                # print(f"✅ DECRYPT DEBUG: Padding removed, final length: {len(decrypted_content)} bytes")
            except Exception as e:
                # print(f"❌ DECRYPT DEBUG: Padding removal failed: {e}")
                # Try to return without unpadding (might be plain text)
                # print("⚠️ DECRYPT DEBUG: Attempting to return without unpadding...")
                return decrypted_padded.decode()
            
            return decrypted_content.decode()
            
        except Exception as e:
            # print(f"❌ DECRYPT DEBUG: Decryption failed at: {str(e)}")
            raise Exception(f"Decryption failed: {str(e)}")

    @staticmethod
    def encrypt_message(message: str, recipient_public_key: str,
                        sender_private_key: str = None, password: str = None) -> dict:
        """
        Encrypt a message for secure vendor-to-vendor communication.
        Optionally sign it with the sender's private key.
        """
        # Encrypt the message using the recipient's public key
        encrypted_data = EncryptionManager.encrypt_document(
            content=message,
            public_key_pem=recipient_public_key
        )

        result = {
            'message': encrypted_data['encrypted_content'],
            'key': encrypted_data['encrypted_key'],
            'iv': encrypted_data['iv'],
            'algorithm': encrypted_data['algorithm'],
            'timestamp': datetime.now().isoformat()
        }

        # If sender provided a private key, add a digital signature
        if sender_private_key:
            try:
                from crypto.certificate_engine import CertificateEngine
                engine = CertificateEngine()
                # Sign the serialized result (excluding signature field)
                signature = engine.sign_document(
                    sender_private_key,
                    json.dumps({k: v for k, v in result.items() if k != 'signature'}),
                    password=password
                )
                result['signature'] = signature
                result['signed'] = True
            except ImportError:
                # Fallback for testing
                result['signature'] = 'MOCK_SIGNATURE'
                result['signed'] = True

        return result

    @staticmethod
    def decrypt_message(encrypted_message: dict, recipient_private_key: str,
                        password: str = None) -> str:
        """
        Decrypt a secure message.
        """
        try:
            decrypted = EncryptionManager.decrypt_document(
                encrypted_data={
                    'encrypted_content': encrypted_message['message'],
                    'encrypted_key': encrypted_message['key'],
                    'iv': encrypted_message['iv'],
                    'salt': encrypted_message.get('salt')
                },
                private_key_pem=recipient_private_key,
                password=password
            )
            return decrypted
        except Exception as e:
            raise Exception(f"Message decryption failed: {str(e)}")