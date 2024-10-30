# Encryption-Decryption-tool
This repository contains a Python-based command-line tool for securely encrypting and decrypting files and messages. It uses advanced security practices to ensure data confidentiality and offers a user-friendly interface with enhanced error handling and retry limits.
Features
Password-Based Key Generation: Utilizes PBKDF2 (Password-Based Key Derivation Function 2) to generate secure encryption keys from user-provided passwords.
Strong Password Requirements: Enforces password security rules, including length and character variety (uppercase, lowercase, numbers, and special characters).
Environment Variable Storage: Sensitive data, such as file paths, are stored in environment variables for added security.
Encryption and Decryption Functions: Supports secure AES encryption with automated key management via the cryptography library's Fernet module.
Retry Limit and Secure File Deletion: Limits decryption attempts to 5. If the correct password is not entered within these attempts, the file is securely deleted.
Enhanced User Interface: Command-line prompts and error messages guide users through the encryption and decryption processes.
Requirements
Python 3.8+
Python Libraries:
cryptography
Install required libraries with:

bash
Copy code
pip install cryptography
Getting Started
Clone the Repository:

bash
Copy code
git clone https://github.com/Mwantech/Encryption-Decryption-tool.git
cd Encryption-Decryption-tool
Set Environment Variables:

Set file paths and other sensitive data as environment variables. This can be done in your terminal session or within the script if needed for testing.
Example:

bash
Copy code
export SECRET_FILE_PATH="/path/to/your/file.txt"
export KEY_FILE_PATH="/path/to/your/keyfile.key"
Run the Program:

bash
Copy code
python secure_encrypt_decrypt.py
Follow CLI Prompts:

Enter a strong password when prompted to generate the encryption key.
Select whether to encrypt or decrypt a file or message.
Provide the necessary file paths and confirm actions through the CLI.
Usage
Encrypting a File
Enter a strong password when prompted. Ensure it meets security requirements:
Minimum 8 characters, with at least one uppercase letter, one lowercase letter, one number, and one special character.
Select the file to encrypt by following the prompt.
Store the generated key and salt safely for future decryption.
Decrypting a File
Enter the password used during encryption.
After 5 unsuccessful attempts, the file will be automatically deleted to prevent unauthorized access.
Error Handling
File Not Found: Alerts if the specified file path is incorrect.
Incorrect Password Attempts: Limits attempts to 5, after which the file is deleted.
Environment Variable Errors: Notifies if required environment variables are missing.
Security Considerations
PBKDF2 with Salt: Each encryption session generates a unique salt, stored securely for future decryption.
Password Strength Check: Ensures that only strong passwords are used for encryption.
Secure File Deletion: After reaching the maximum retry limit, files are securely deleted.
Troubleshooting
Ensure all dependencies are installed (cryptography).
Confirm environment variables are correctly set for file paths.
Use strong passwords to prevent security issues.
License
This project is open-source under the MIT License. See the LICENSE file for more details.
