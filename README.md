# 🛡️ Cyber Security Mini Projects

A collection of educational cybersecurity tools written in Python for learning and ethical security practices.

## 📋 Projects Overview

| Task | Name | Description | Key Features |
|------|------|-------------|--------------|
| 1 | File Integrity Checker | Monitors file changes using SHA-256 hashes | JSON database, scan logs, change detection |
| 2 | Penetration Testing Toolkit | Multi-tool for security reconnaissance | Port scanning, directory busting, brute-force demo |
| 3 | Vulnerable Login App | Safe local target for testing | Flask web app, demo credentials |
| 4 | AES File Encryptor | Secure file encryption/decryption | AES-256-GCM, password-based keys |

> ⚠️ **Legal Notice**: These tools are for **educational purposes only**. Use only on systems you own or have explicit permission to test.

---

## 🚀 Quick Setup

### Prerequisites
- Python 3.8+
- Terminal/Command Line knowledge
- Virtual Environment (recommended)

### One-Time Installation

```bash
# Clone and navigate to project
git clone <your-repo-url>
cd Cyber_Security_Projects

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Linux/macOS:
source venv/bin/activate
# Windows:
# venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

**Manual Installation** (if requirements.txt missing):
```bash
pip install flask cryptography requests beautifulsoup4
```

---

## 📁 Project Files Structure

```
Cyber_Security_Projects/
├── task1_file_integrity.py    # File integrity monitoring
├── pentest_toolkit.py         # Security testing tools
├── vuln_login.py             # Vulnerable web app (demo)
├── task4_encryptor.py        # File encryption/decryption
├── requirements.txt          # Python dependencies
└── README.md                # This file
```

---

## 🛠️ Detailed Usage Guide

## 1. Task 1 - File Integrity Checker

### 🎯 Purpose
Monitor files for unauthorized changes using SHA-256 hashing.

### 🏃‍♂️ How to Run
```bash
python task1_file_integrity.py
```

### 📊 Sample Output
```
=== File Integrity Checker ===
1. Scan Folder for Changes
2. View Stored File Hashes  
3. View Scan History
4. Reset Database
5. Exit

Choose option (1-5): 1

Enter folder path: test_files

[🔍] Scanning folder: test_files
[📊] Scan Report:
  Modified   : 2 files
  New        : 3 files  
  Unchanged  : 15 files
  Missing    : 1 files

[✅] Report saved to 'scan_report.txt'
[✅] Hash database updated
```

### 📝 Generated Files
- `hashes.json` - Stores file hashes
- `scan_report.txt` - Scan history with timestamps

---

## 2. Task 2 - Penetration Testing Toolkit

### 🎯 Purpose
Multi-tool for security assessment and reconnaissance.

### 🏃‍♂️ How to Run
```bash
python pentest_toolkit.py
```

### 🎪 Menu Options & Examples

#### Option 1: Port Scanner
```
=== Penetration Testing Toolkit ===
1. Port Scanner
2. Directory Scanner  
3. Brute Force Demo
4. Exit

Choose option (1-4): 1

Enter target host: scanme.nmap.org
Start port: 80
End port: 100
Threads: 50

[🔍] Scanning ports 80-100 on scanme.nmap.org...
[✅] Scan completed in 1.23 seconds
[📈] Open ports found:
  - Port 80 (HTTP)
  - Port 22 (SSH)
```

#### Option 2: Directory Scanner
```
Choose option (1-4): 2

Enter base URL: http://example.com
Wordlist file (press Enter for default): 

[🔍] Scanning for directories...
[✅] Scan completed!
[📈] Interesting endpoints found:
  - http://example.com/admin (302 Redirect)
  - http://example.com/backup (200 OK)
  - http://example.com/config (403 Forbidden)
```

#### Option 3: Brute Force Demo
**First, start the vulnerable app:**
```bash
# Terminal 2 - Run this first!
python vuln_login.py
```

**Then run brute force:**
```
Choose option (1-4): 3

Login URL: http://127.0.0.1:5000/login
Username field: username
Password field: password 
Usernames (comma-separated): admin,test,user
Passwords (comma-separated): admin,123456,password
Delay between attempts (seconds): 0.5
Log file: bruteforce_log.txt

[🔐] Starting brute force attack...
[1/9] admin:admin → SUCCESS (302 Redirect)
[2/9] admin:123456 → FAILED (200 OK)
...
[✅] Potential credentials found:
  - admin:admin (302 Redirect)
```

---

## 3. Task 3 - Vulnerable Login App

### 🎯 Purpose
Safe local web application for testing security tools.

### 🏃‍♂️ How to Run
```bash
python vuln_login.py
```

### 📊 Sample Output
```
[🌐] Starting Vulnerable Login App...
 * Serving Flask app 'vuln_login'
 * Debug mode: off
 * Running on http://127.0.0.1:5000

[🔑] Demo credentials loaded:
   admin / admin
   test / 123456

[📝] Ready for testing!
```

### 🌐 Access the App
Open your browser and go to: `http://127.0.0.1:5000`

### 🔑 Test Credentials
| Username | Password | Access |
|----------|----------|--------|
| `admin` | `admin` | Full access |
| `test` | `123456` | Limited access |

---

## 4. Task 4 - AES File Encryptor

### 🎯 Purpose
Secure file encryption and decryption using AES-256-GCM.

### 🏃‍♂️ How to Run
```bash
python task4_encryptor.py
```

### 🔒 Encryption Example
```
=== AES-256-GCM File Encryptor ===
1. Encrypt File
2. Decrypt File
3. Exit

Choose option (1-3): 1

Enter file path to encrypt: secret_document.txt
Enter password: [hidden]
Confirm password: [hidden]

[🔐] Encrypting file...
[✅] Encryption successful!
📁 Input: secret_document.txt
📄 Output: secret_document.txt.enc
🔐 Method: AES-256-GCM
```

### 🔓 Decryption Example
```
Choose option (1-3): 2

Enter file path to decrypt: secret_document.txt.enc
Enter password: [hidden]

[🔓] Decrypting file...
[✅] Decryption successful!
📁 Input: secret_document.txt.enc  
📄 Output: secret_document_decrypted.txt
```

### 🛡️ Security Features
- AES-256-GCM encryption
- PBKDF2 key derivation
- Tamper detection
- Secure password handling

---

## 🔧 Troubleshooting Guide

### ❌ Common Issues & Solutions

**1. Module Import Errors**
```bash
# Solution: Reactivate virtual environment
source venv/bin/activate  # Linux/macOS
# OR
venv\Scripts\activate    # Windows
pip install -r requirements.txt
```

**2. Vulnerable App Not Accessible**
```bash
# Check if app is running
python vuln_login.py

# Test connectivity
curl http://127.0.0.1:5000
```

**3. Port Scanner Shows No Results**
- Test on `localhost` first
- Reduce port range (1-100)
- Check firewall settings
- Use known test domains like `scanme.nmap.org`

**4. File Permission Errors**
- Run as administrator (if needed)
- Check file/folder permissions
- Use absolute paths instead of relative

### 📁 Generated Files (Ignore in Git)
Add to `.gitignore`:
```
hashes.json
scan_report.txt
bruteforce_log.txt
*.enc
venv/
__pycache__/
```

---

## 🎯 Learning Objectives

| Task | Skills Learned |
|------|----------------|
| 1 | File hashing, integrity monitoring, change detection |
| 2 | Network scanning, web enumeration, automation |
| 3 | Web app security, authentication systems |
| 4 | Cryptography, secure key management, file protection |

---

## ⚠️ Responsible Usage

✅ **Allowed Uses:**
- Educational environments
- Personal systems testing
- Authorized penetration testing
- Security research with permission

❌ **Prohibited Uses:**
- Unauthorized system access
- Network attacks without permission
- Illegal activities
- Malicious purposes

**You are solely responsible for complying with local laws and regulations.**
