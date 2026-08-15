# Secure File Transfer Application

## Overview

The **Secure File Transfer Application** is a cybersecurity-focused project developed as part of the **Rhombix Technologies Cyber Security Internship Program**. The application provides a secure mechanism for transferring files by implementing encryption, integrity verification, access control, and audit logging.

The project demonstrates fundamental cybersecurity principles by ensuring that transferred files remain confidential, unaltered, and accessible only to authorized users.

---

## Features

### User Authentication

* Username and password-based login system
* Authorized user access only
* Access control implementation

### File Encryption

* End-to-End file encryption using the **Fernet (AES-based) encryption algorithm**
* Protects file confidentiality during transfer

### Integrity Verification

* SHA-256 hash generation
* File tampering detection
* Integrity validation before decryption

### Audit Logging

* Records user activities
* Maintains a security audit trail
* Tracks encryption, decryption, and verification events

### File Decryption

* Secure recovery of original files
* Decryption available only after integrity verification

---

## Technologies Used

* Python 3.x
* Cryptography Library (Fernet)
* Hashlib (SHA-256)
* JSON
* File Handling
* Datetime Module

---

## Project Structure

```text
SecureFileTransfer/
│
├── main.py
├── auth.py
├── crypto_utils.py
├── hash_utils.py
├── logger.py
│
├── users.json
├── secret.key
├── logs.txt
├── requirements.txt
│
├── sample.txt
├── sample.txt.encrypted
├── sample.txt.encrypted.hash
│
└── README.md
```

---

## Installation

### 1. Clone Repository

```bash
git clone https://github.com/yourusername/RhombixTechnologies_Tasks.git
cd RhombixTechnologies_Tasks
```

### 2. Create Virtual Environment

```bash
python -m venv venv
```

### 3. Activate Virtual Environment

#### Windows

```bash
venv\Scripts\activate
```

#### Linux/Mac

```bash
source venv/bin/activate
```

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Running the Application

```bash
python main.py
```

---

## Login Credentials

### Administrator

```text
Username: admin
Password: admin123
```

### User

```text
Username: user1
Password: password123
```

---

## Usage

### Encrypt a File

1. Login to the application
2. Select "Encrypt File"
3. Enter file name
4. Application creates:

   * Encrypted file
   * SHA-256 hash file

### Verify Integrity

1. Select "Verify Integrity"
2. Enter encrypted file name
3. Application validates file hash

### Decrypt File

1. Select "Decrypt File"
2. Enter encrypted file name
3. Original file is restored

### View Audit Logs

1. Select "View Audit Logs"
2. Review recorded security events

---

## Security Features

### Confidentiality

Files are encrypted before transfer using Fernet symmetric encryption.

### Integrity

SHA-256 hashing ensures files have not been modified during transfer.

### Access Control

Only authenticated users can access application functionality.

### Audit Logging

All critical security events are recorded for monitoring and analysis.

---

## Sample Audit Log

```text
[2026-08-15 11:05:21] User admin logged in
[2026-08-15 11:05:32] Encrypted sample.txt
[2026-08-15 11:05:33] Hash generated for sample.txt.encrypted
[2026-08-15 11:05:45] Integrity verified for sample.txt.encrypted
[2026-08-15 11:05:58] Decrypted sample.txt.encrypted
```

---

## Learning Outcomes

This project provided practical experience in:

* Secure File Transfer Systems
* Cryptography Fundamentals
* Encryption and Decryption
* Integrity Verification
* Authentication Mechanisms
* Access Control
* Security Logging
* Python-Based Cybersecurity Development

---

## Internship Information

**Organization:** Rhombix Technologies

**Domain:** Cyber Security

**Project:** Secure File Transfer Application

---

## Author

**Hassan Mujtaba**

Software Engineering Student

Cyber Security Intern – Rhombix Technologies
