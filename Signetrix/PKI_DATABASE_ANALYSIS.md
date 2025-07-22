# Signetrix - PKI System Database Analysis & Implementation

A professional analysis of the Signetrix PKI system's database architecture, security features, and integration with modern cryptographic workflows.

---

## 🚀 Executive Summary

Signetrix leverages a robust, extensible SQLite database to manage users, certificates, signed documents, audit logs, and security events. The schema is designed for strong security, data integrity, and real-world PKI workflows, including password-based authentication, private key encryption, and challenge-response mechanisms.

---

## 📋 Requirements Table

| Requirement Area        | Status      | Notes/Improvements                     |
| ----------------------- | ----------- | -------------------------------------- |
| PKI User Auth           | ✔️ Complete | Password, challenge-response, CA       |
| Document Signing/Verify | ✔️ Complete | RSA-PSS, SHA-256, cert check           |
| Security Features       | ✔️ Complete | Password hash, key encryption, lockout |
| Key Management          | ✔️ Partial  | No explicit revocation/CRL             |
| Use Case                | ✔️ Complete | Help button, real-world scenario       |
| Testing/Validation      | ✔️ Complete | Interactive CLI, all test types        |

---

## 🗄️ Database Schema Overview

### **1. Users Table**

```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    private_key_path TEXT NOT NULL,
    public_key_path TEXT NOT NULL,
    certificate_path TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    is_active BOOLEAN DEFAULT 1,
    failed_attempts INTEGER DEFAULT 0,
    lockout_until TIMESTAMP
);
```

- **password_hash, salt**: Secure password storage (PBKDF2-HMAC-SHA256)
- **failed_attempts, lockout_until**: Account lockout after 5 failed logins

### **2. Certificates Table**

```sql
CREATE TABLE certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    serial_number TEXT UNIQUE NOT NULL,
    subject_name TEXT NOT NULL,
    issuer_name TEXT NOT NULL,
    valid_from TIMESTAMP NOT NULL,
    valid_until TIMESTAMP NOT NULL,
    certificate_path TEXT NOT NULL,
    is_revoked BOOLEAN DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);
```

- **issuer_name**: Application acts as its own CA
- **is_revoked**: (Planned) For future key revocation/CRL

### **3. Signed Documents Table**

```sql
CREATE TABLE signed_documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    document_name TEXT NOT NULL,
    document_path TEXT NOT NULL,
    signature_path TEXT NOT NULL,
    document_hash TEXT NOT NULL,
    signature_algorithm TEXT DEFAULT 'RSA-PSS',
    hash_algorithm TEXT DEFAULT 'SHA-256',
    signed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_verified BOOLEAN DEFAULT 0,
    verification_count INTEGER DEFAULT 0,
    last_verified TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);
```

### **4. Verification Logs Table**

```sql
CREATE TABLE verification_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id INTEGER,
    verifier_info TEXT,
    verification_result BOOLEAN NOT NULL,
    verification_details TEXT,
    verified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (document_id) REFERENCES signed_documents (id)
);
```

### **5. System Audit Log Table**

```sql
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    details TEXT,
    ip_address TEXT,
    user_agent TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);
```

---

## 🔒 Security Features in Database

- **Password Hashing**: PBKDF2-HMAC-SHA256 with unique salt per user
- **Private Key Encryption**: AES-256, password-protected PEM files
- **Challenge-Response**: Challenge file and signature tracked per login
- **Account Lockout**: Tracked via failed_attempts and lockout_until
- **Audit Logging**: All critical actions (registration, login, sign, verify, password change)
- **Certificate Authority**: Application issues and validates all certificates
- **Key Revocation**: (Planned) Schema supports future CRL/OCSP

---

## 🔄 Process Flows & Integration

### **User Registration**

```
Input: Username, Password →
Generate Salt, Hash Password →
Generate RSA Keys →
Encrypt Private Key (AES-256, password) →
Create CA-signed Certificate →
Store Files →
Insert into users, certificates →
Audit Log
```

### **User Authentication**

```
Input: Username, Password →
Check lockout status →
Verify password hash →
If valid: Generate challenge file →
User signs challenge →
Verify signature (proof of possession) →
Update last_login, reset failed_attempts →
Audit Log
```

### **Document Signing**

```
Input: Document →
Hash (SHA-256) →
Decrypt Private Key (password) →
Sign (RSA-PSS) →
Store signature, update signed_documents →
Audit Log
```

### **Document Verification**

```
Input: Document, Signature, Certificate →
Hash (SHA-256) →
Verify signature (RSA-PSS) →
Check certificate validity (CA) →
Update verification_logs, signed_documents →
Audit Log
```

### **Password Change**

```
Input: Current Password, New Password →
Verify current password →
Decrypt private key →
Re-encrypt with new password →
Update password_hash, salt, private_key_path →
Audit Log
```

---

## 📈 Metrics & Audit

- **Users**: Total, active, locked
- **Documents**: Signed, verified, tampered
- **Audit Events**: Registration, login, sign, verify, password change
- **Account Lockouts**: Tracked and timestamped

---

## 🧪 Testing & Validation

- **Interactive CLI**: `python test_security_features.py` (menu-driven test selection)
- **Test Cases**: User registration, authentication, signing, verification, lockout, attack simulations

---

## 🛡️ Implementation Benefits

- **Data Integrity**: Foreign keys, constraints, ACID compliance
- **Security**: Password hashing, key encryption, challenge-response, lockout
- **Auditability**: Full event logging for compliance and forensics
- **Extensibility**: Schema supports future features (revocation, advanced audit, analytics)

---

## 🏆 Conclusion

Signetrix’s database layer is engineered for security, integrity, and extensibility. It supports all modern PKI workflows, robust authentication, and auditability, making it suitable for real-world secure document management and digital trust applications.

**Signetrix: Secure. Professional. Trusted.**
