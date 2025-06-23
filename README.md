# A-PassGenerator

![Application Screenshot](/screenshots/main-ui.png)

In a world where cyber threats are rising and password fatigue is real, our Password Generator Tool offers a smart solution for both everyday users and security-conscious professionals. Instead of remembering or storing passwords, users generate strong, unique passwords on demand using simple inputs like app name, user ID, and a personal digit—all secured by a locally encrypted master password.

The tool uses deterministic logic, meaning the same input always creates the same password—without ever storing or syncing sensitive data. With built-in password rules (uppercase, lowercase, digits, symbols), clipboard integration, and an optional encryption/decryption utility, it provides top-tier security with zero storage risk.

Whether you’re managing dozens of logins or just want peace of mind online, our tool delivers simplicity without compromise—keeping your digital life safe, private, and stress-free.

## Usage

### First Run

- Set a 6+ character PIN
- Create your master password
- The application will create an encrypted master file

### Daily Use

- Enter your PIN to unlock
- Enter an identifier (e.g., "gmail")
- Click "Generate Password" - password is copied to clipboard
- Use "Encryption Tools" for secure messaging/2FA codes

## Features

- 🔄 Passwords are generated, not stored
- 🔒 Device-bound encryption (requires original hardware)
- 🔑 Deterministic password generation
- ⏱️ Automatic session timeout (2 minutes)
- 📋 Clipboard auto-clear
- ✉️ Secure text/2FA codes encryption tools
- 🛡️ Memory-safe storage of sensitive data
- 🚪 Exit on wrong PIN (brute-force protection)

## Security Model

- **Device Binding**: Uses MAC address as salt
- **Key Derivation**: 600,000 PBKDF2-HMAC iterations
- **Password Generation**: HMAC-SHA256 with master key
- **Memory Protection**: SecureString class wipes sensitive data
- **PIN Protection**: Minimum 6 characters, exit on wrong attempt

## Installation

1. Install Python 3.8+
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the application:
   ```bash
   python PassGenerator.py
   ```
### or

- Just run the "A-PassGenerator.exe" in EXE folder
**Note-:** Don't move the .exe file (Create a shortcut if you want). 
   
## Cryptography Overview

### Core Cryptographic Techniques

| Technique   | Purpose   | Implementation Details |
|-------------|-----------|------------------------|
| **AES-128-CBC** | Master password encryption | Fernet authenticated encryption |
| **PBKDF2-HMAC-SHA256** | Key derivation from PIN | 600,000 iterations, device-specific salt |
| **HMAC-SHA256** | Password generation | Master key + service identifier |
| **Device-Specific Salting** | Key derivation protection | SHA256(MAC address) |
| **Secure Memory Handling** | Runtime protection | Byte-level overwriting |   
   

## Contributing

Contributions are welcome! Please submit issues or pull requests for:
- Security improvements
- Bug fixes
- UX enhancements
- Documentation updates
