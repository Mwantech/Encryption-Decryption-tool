import os
import sys
import re
import base64
import getpass
import secrets
from pathlib import Path
from typing import Tuple, Optional, Union
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidKey

class SecureHandler:
    SALT_LENGTH = 16
    ITERATIONS = 100000
    MAX_RETRIES = 5
    
    def __init__(self):
        self.env_setup()
    
    @staticmethod
    def env_setup():
        """Set up environment variables if they don't exist."""
        if 'ENCRYPTION_OUTPUT_DIR' not in os.environ:
            os.environ['ENCRYPTION_OUTPUT_DIR'] = str(Path.home() / 'encrypted_files')
        
        # Create output directory if it doesn't exist
        Path(os.environ['ENCRYPTION_OUTPUT_DIR']).mkdir(parents=True, exist_ok=True)
    
    def validate_password(self, password: str) -> Tuple[bool, str]:
        """
        Validate password meets security requirements.
        Returns: (is_valid, error_message)
        """
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        if not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        if not re.search(r'\d', password):
            return False, "Password must contain at least one number"
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "Password must contain at least one special character"
        return True, ""

    def generate_key(self, password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """Generate encryption key from password using PBKDF2."""
        if salt is None:
            salt = secrets.token_bytes(self.SALT_LENGTH)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.ITERATIONS
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt

    def get_file_stem(self, file_path: str) -> str:
        """Extract the correct file stem for salt file lookup."""
        path = Path(file_path)
        stem = path.stem
        if stem.endswith('_encrypted'):
            stem = stem[:-10]
        return stem

    def get_salt_path(self, identifier: str) -> Path:
        """Get the full path for the salt file."""
        return Path(os.environ['ENCRYPTION_OUTPUT_DIR']) / f"{identifier}.salt"

    def verify_file_for_decryption(self, file_path: str) -> Tuple[bool, str]:
        """
        Verify that all required files exist for decryption.
        Returns: (is_ready, error_message)
        """
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                return False, f"Encrypted file not found: {file_path}"
            
            file_stem = self.get_file_stem(str(file_path))
            salt_path = self.get_salt_path(file_stem)
            
            if not salt_path.exists():
                return False, (f"Salt file not found: {salt_path}\n"
                             f"Please ensure the salt file is in the correct location: {os.environ['ENCRYPTION_OUTPUT_DIR']}")
            
            return True, ""
        except Exception as e:
            return False, f"Error verifying files: {str(e)}"

    def encrypt_message(self, message: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """Encrypt a message using password-based encryption."""
        try:
            # Get and validate password
            while True:
                password = getpass.getpass("Enter encryption password: ")
                is_valid, error_msg = self.validate_password(password)
                if is_valid:
                    break
                print(f"Invalid password: {error_msg}")
            
            # Generate key and salt
            key, salt = self.generate_key(password)
            fernet = Fernet(key)
            
            # Encrypt message
            encrypted_data = fernet.encrypt(message.encode())
            
            # Generate a unique identifier for this message
            message_id = secrets.token_hex(8)
            
            # Save salt file
            salt_path = self.get_salt_path(message_id)
            with open(salt_path, 'wb') as f:
                f.write(salt)
            
            # Convert encrypted data to base64 for easy sharing
            encrypted_message = base64.urlsafe_b64encode(encrypted_data).decode()
            
            print(f"\nMessage encrypted successfully!")
            print(f"Salt file location: {salt_path}")
            print(f"Message ID (needed for decryption): {message_id}")
            print("\nIMPORTANT: Keep both the Message ID and salt file safe - you'll need them for decryption!")
            
            return True, encrypted_message, message_id
            
        except Exception as e:
            print(f"Encryption error: {str(e)}")
            return False, None, None

    def decrypt_message(self, encrypted_message: str, message_id: str) -> Tuple[bool, Optional[str]]:
        """Decrypt a message with retry limit."""
        salt_path = self.get_salt_path(message_id)
        
        if not salt_path.exists():
            print(f"Salt file not found: {salt_path}")
            return False, None
        
        retries = 0
        while retries < self.MAX_RETRIES:
            try:
                # Load salt
                with open(salt_path, 'rb') as f:
                    salt = f.read()
                
                # Get password and generate key
                password = getpass.getpass("Enter decryption password: ")
                key, _ = self.generate_key(password, salt)
                fernet = Fernet(key)
                
                # Decode and decrypt message
                encrypted_data = base64.urlsafe_b64decode(encrypted_message.encode())
                decrypted_data = fernet.decrypt(encrypted_data)
                decrypted_message = decrypted_data.decode()
                
                print("\nMessage decrypted successfully!")
                return True, decrypted_message
                
            except InvalidToken:
                retries += 1
                remaining = self.MAX_RETRIES - retries
                if remaining > 0:
                    print(f"Incorrect password. {remaining} attempts remaining.")
                else:
                    print("\nMaximum retry attempts reached. Salt file will be deleted for security.")
                    self._secure_delete_file(salt_path)
                    return False, None
                    
            except Exception as e:
                print(f"Decryption error: {str(e)}")
                return False, None

    def encrypt_file(self, file_path: str) -> bool:
        """Encrypt a file using password-based encryption."""
        try:
            # Get and validate password
            while True:
                password = getpass.getpass("Enter encryption password: ")
                is_valid, error_msg = self.validate_password(password)
                if is_valid:
                    break
                print(f"Invalid password: {error_msg}")
            
            # Generate key and salt
            key, salt = self.generate_key(password)
            fernet = Fernet(key)
            
            # Read file content
            file_path = Path(file_path)
            if not file_path.exists():
                raise FileNotFoundError(f"File not found: {file_path}")
            
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Encrypt data
            encrypted_data = fernet.encrypt(file_data)
            
            # Save encrypted file and salt
            output_path = Path(os.environ['ENCRYPTION_OUTPUT_DIR']) / f"{file_path.stem}_encrypted{file_path.suffix}"
            with open(output_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Save salt file with original file stem
            salt_path = self.get_salt_path(file_path.stem)
            with open(salt_path, 'wb') as f:
                f.write(salt)
            
            print(f"\nFile encrypted successfully!")
            print(f"Encrypted file location: {output_path}")
            print(f"Salt file location: {salt_path}")
            print("\nIMPORTANT: Keep the salt file safe - you'll need it for decryption!")
            return True
            
        except Exception as e:
            print(f"Encryption error: {str(e)}")
            return False

    def decrypt_file(self, file_path: str) -> bool:
        """Decrypt a file with retry limit."""
        # Verify files before attempting decryption
        is_ready, error_msg = self.verify_file_for_decryption(file_path)
        if not is_ready:
            print(f"\nDecryption preparation failed:")
            print(error_msg)
            return False

        file_path = Path(file_path)
        file_stem = self.get_file_stem(str(file_path))
        retries = 0
        
        while retries < self.MAX_RETRIES:
            try:
                # Load salt
                salt_path = self.get_salt_path(file_stem)
                with open(salt_path, 'rb') as f:
                    salt = f.read()
                
                # Get password and generate key
                password = getpass.getpass("Enter decryption password: ")
                key, _ = self.generate_key(password, salt)
                fernet = Fernet(key)
                
                # Read and decrypt file
                with open(file_path, 'rb') as f:
                    encrypted_data = f.read()
                
                decrypted_data = fernet.decrypt(encrypted_data)
                
                # Save decrypted file
                output_path = Path(os.environ['ENCRYPTION_OUTPUT_DIR']) / f"{file_stem}_decrypted{file_path.suffix}"
                with open(output_path, 'wb') as f:
                    f.write(decrypted_data)
                
                print(f"\nFile decrypted successfully!")
                print(f"Decrypted file location: {output_path}")
                return True
                
            except InvalidToken:
                retries += 1
                remaining = self.MAX_RETRIES - retries
                if remaining > 0:
                    print(f"Incorrect password. {remaining} attempts remaining.")
                else:
                    print("\nMaximum retry attempts reached. Deleting encrypted file for security.")
                    self._secure_delete_file(file_path)
                    self._secure_delete_file(salt_path)
                    return False
                    
            except Exception as e:
                print(f"Decryption error: {str(e)}")
                return False

    def _secure_delete_file(self, file_path: Path):
        """Securely delete a file by overwriting with random data before deletion."""
        try:
            if file_path.exists():
                # Overwrite file with random data multiple times
                file_size = file_path.stat().st_size
                for _ in range(3):  # Overwrite 3 times
                    with open(file_path, 'wb') as f:
                        f.write(secrets.token_bytes(file_size))
                # Finally delete the file
                file_path.unlink()
                print(f"Securely deleted: {file_path}")
        except Exception as e:
            print(f"Error during secure deletion: {str(e)}")

def main():
    handler = SecureHandler()
    
    while True:
        print("\nSecure File and Message Encryption/Decryption Tool")
        print("1. Encrypt file")
        print("2. Decrypt file")
        print("3. Encrypt message")
        print("4. Decrypt message")
        print("5. Exit")
        
        choice = input("\nEnter your choice (1-5): ")
        
        if choice == "1":
            file_path = input("Enter path to file to encrypt: ")
            handler.encrypt_file(file_path)
        elif choice == "2":
            print("\nNOTE: Make sure you have both the encrypted file and its corresponding .salt file")
            print(f"Salt files are stored in: {os.environ['ENCRYPTION_OUTPUT_DIR']}")
            file_path = input("Enter path to encrypted file: ")
            handler.decrypt_file(file_path)
        elif choice == "3":
            message = input("Enter message to encrypt: ")
            success, encrypted_message, message_id = handler.encrypt_message(message)
            if success:
                print("\nEncrypted message:")
                print(encrypted_message)
        elif choice == "4":
            encrypted_message = input("Enter encrypted message: ")
            message_id = input("Enter message ID: ")
            success, decrypted_message = handler.decrypt_message(encrypted_message, message_id)
            if success:
                print("\nDecrypted message:")
                print(decrypted_message)
        elif choice == "5":
            print("Exiting...")
            sys.exit(0)
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()