#!/usr/bin/env python3
"""
Signetrix - PKI Document Signing System

A professional, integrated application for secure document signing, verification, and user authentication.
Features:
- User registration and authentication (password, challenge-response)
- CA-signed certificates and private key encryption
- Document signing and verification
- Account lockout, audit logging, and more
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
import sys
import hashlib
import base64
import threading
import time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, BestAvailableEncryption, NoEncryption
from cryptography import x509
from cryptography.x509.oid import NameOID
import sqlite3
import json
from datetime import datetime, timedelta, timezone
import secrets
import re
import shutil
import tempfile
from typing import Optional, Any, Dict, List, Tuple, Callable

# =====================
# UI Color and Font Schemes
# =====================

class Colors:
    """Color palette for Signetrix UI."""
    # Primary Colors
    PRIMARY_DARK = '#1a1a2e'      # Deep navy blue
    PRIMARY_BLUE = '#16213e'      # Dark blue
    ACCENT_BLUE = '#0f3460'       # Medium blue
    LIGHT_BLUE = '#533483'        # Purple-blue

    # Background Colors
    BG_MAIN = '#f8f9fa'           # Light gray background
    BG_CARD = '#ffffff'           # White cards
    BG_HEADER = '#2c3e50'         # Dark header
    BG_SIDEBAR = '#34495e'        # Sidebar

    # Text Colors
    TEXT_PRIMARY = '#2c3e50'      # Dark text
    TEXT_SECONDARY = '#7f8c8d'    # Gray text
    TEXT_LIGHT = '#bdc3c7'        # Light gray text
    TEXT_WHITE = '#ffffff'        # White text

    # Status Colors
    SUCCESS = '#27ae60'           # Green
    WARNING = '#f39c12'           # Orange
    ERROR = '#e74c3c'             # Red
    INFO = '#3498db'              # Blue

    # Interactive Colors
    BUTTON_PRIMARY = '#3498db'    # Primary button
    BUTTON_SUCCESS = '#27ae60'    # Success button
    BUTTON_WARNING = '#f39c12'    # Warning button
    BUTTON_DANGER = '#e74c3c'     # Danger button
    BUTTON_HOVER = '#2980b9'      # Hover state

    # Border Colors
    BORDER_LIGHT = '#ecf0f1'      # Light border
    BORDER_MEDIUM = '#bdc3c7'     # Medium border
    BORDER_DARK = '#95a5a6'       # Dark border

class Fonts:
    """Font families and sizes for Signetrix UI."""
    # Font families (use single font name for tkinter compatibility)
    PRIMARY = 'Segoe UI'
    SECONDARY = 'Consolas'
    FALLBACK = 'Arial'

    # Font sizes
    TITLE = 24
    HEADING = 18
    SUBHEADING = 14
    BODY = 11
    SMALL = 9
    CAPTION = 8

# =====================
# Database Management
# =====================

class DatabaseManager:
    """
    Handles all database operations for Signetrix, including user, certificate,
    document, verification, and audit log management.
    """
    def __init__(self, db_path: str = "pki_system.db") -> None:
        """
        Initialize the database manager and ensure schema is up to date.
        :param db_path: Path to the SQLite database file.
        """
        self.db_path = db_path
        self.init_database()
    
    def init_database(self) -> None:
        """
        Initialize database with required tables and perform migrations if needed.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Users table (add password_hash if not exists)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    private_key_path TEXT NOT NULL,
                    public_key_path TEXT NOT NULL,
                    certificate_path TEXT NOT NULL,
                    password_hash TEXT,
                    salt TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1,
                    failed_attempts INTEGER DEFAULT 0,
                    lockout_until TIMESTAMP
                )
            ''')
            
            # Migration for password_hash and salt
            cursor.execute("PRAGMA table_info(users)")
            columns = [column[1] for column in cursor.fetchall()]
            if 'password_hash' not in columns:
                cursor.execute('ALTER TABLE users ADD COLUMN password_hash TEXT')
            if 'salt' not in columns:
                cursor.execute('ALTER TABLE users ADD COLUMN salt TEXT')
            if 'failed_attempts' not in columns:
                cursor.execute('ALTER TABLE users ADD COLUMN failed_attempts INTEGER DEFAULT 0')
            if 'lockout_until' not in columns:
                cursor.execute('ALTER TABLE users ADD COLUMN lockout_until TIMESTAMP')
            
            # Certificates table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS certificates (
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
                )
            ''')
            
            # Signed documents table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS signed_documents (
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
                    is_favorite BOOLEAN DEFAULT 0,
                    category TEXT DEFAULT 'General',
                    tags TEXT DEFAULT '',
                    file_size INTEGER DEFAULT 0,
                    original_path TEXT,
                    notes TEXT DEFAULT '',
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            # Verification logs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS verification_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    document_id INTEGER,
                    verifier_info TEXT,
                    verification_result BOOLEAN NOT NULL,
                    verification_details TEXT,
                    verified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (document_id) REFERENCES signed_documents (id)
                )
            ''')
            
            # System audit log
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    action TEXT NOT NULL,
                    details TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')

            conn.commit()

            # Migrate existing database if needed
            self.migrate_database()

    def migrate_database(self) -> None:
        """
        Migrate database to add new columns if they don't exist (idempotent).
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Check if new columns exist in signed_documents table
            cursor.execute("PRAGMA table_info(signed_documents)")
            columns = [column[1] for column in cursor.fetchall()]

            # Add missing columns
            new_columns = [
                ('is_favorite', 'BOOLEAN DEFAULT 0'),
                ('category', 'TEXT DEFAULT "General"'),
                ('tags', 'TEXT DEFAULT ""'),
                ('file_size', 'INTEGER DEFAULT 0'),
                ('original_path', 'TEXT'),
                ('notes', 'TEXT DEFAULT ""')
            ]

            for column_name, column_def in new_columns:
                if column_name not in columns:
                    try:
                        cursor.execute(f'ALTER TABLE signed_documents ADD COLUMN {column_name} {column_def}')
                        print(f"Added column {column_name} to signed_documents table")
                    except sqlite3.OperationalError as e:
                        if "duplicate column name" not in str(e):
                            print(f"Error adding column {column_name}: {e}")

            conn.commit()
    
    def add_user(self, username: str, private_key_path: str, public_key_path: str, certificate_path: str, password_hash: str, salt: str) -> int:
        """
        Add a new user to the database with password hash and salt.
        :return: The new user's database ID.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO users (username, private_key_path, public_key_path, certificate_path, password_hash, salt)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (username, private_key_path, public_key_path, certificate_path, password_hash, salt))
            user_id = cursor.lastrowid
            conn.commit()
            return user_id
    
    def get_user_by_username(self, username: str) -> Optional[Tuple[Any, ...]]:
        """
        Get user information by username.
        :return: User row as a tuple, or None if not found.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username = ? AND is_active = 1', (username,))
            return cursor.fetchone()
    
    def update_last_login(self, user_id: int) -> None:
        """
        Update the user's last login timestamp.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?
            ''', (user_id,))
            conn.commit()
    
    def add_certificate(self, user_id: int, serial_number: str, subject_name: str, issuer_name: str, 
                       valid_from: str, valid_until: str, certificate_path: str) -> None:
        """
        Add certificate information to the database.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO certificates 
                (user_id, serial_number, subject_name, issuer_name, valid_from, valid_until, certificate_path)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (user_id, serial_number, subject_name, issuer_name, valid_from, valid_until, certificate_path))
            conn.commit()
    
    def add_signed_document(self, user_id: int, document_name: str, document_path: str, signature_path: str, document_hash: str,
                           category: str = 'General', tags: str = '', original_path: str = '', notes: str = '') -> int:
        """
        Add a signed document record to the database with enhanced metadata.
        :return: The new document's database ID.
        """
        # Get file size
        file_size = 0
        try:
            if os.path.exists(document_path):
                file_size = os.path.getsize(document_path)
        except:
            pass

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO signed_documents
                (user_id, document_name, document_path, signature_path, document_hash,
                 category, tags, file_size, original_path, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (user_id, document_name, document_path, signature_path, document_hash,
                  category, tags, file_size, original_path, notes))
            document_id = cursor.lastrowid
            conn.commit()
            return document_id
    
    def add_verification_log(self, document_id: int, verifier_info: str, verification_result: bool, verification_details: str) -> None:
        """
        Add a verification log entry.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO verification_logs 
                (document_id, verifier_info, verification_result, verification_details)
                VALUES (?, ?, ?, ?)
            ''', (document_id, verifier_info, verification_result, verification_details))
            conn.commit()
    
    def log_audit_event(self, user_id: int, action: str, details: Optional[str] = None) -> None:
        """
        Log an audit event for a user.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO audit_log (user_id, action, details)
                VALUES (?, ?, ?)
            ''', (user_id, action, details))
            conn.commit()
    
    def get_user_statistics(self) -> Dict[str, int]:
        """
        Get system statistics (total users, documents, verifications).
        :return: Dictionary of statistics.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Total users
            cursor.execute('SELECT COUNT(*) FROM users WHERE is_active = 1')
            total_users = cursor.fetchone()[0]

            # Total signed documents
            cursor.execute('SELECT COUNT(*) FROM signed_documents')
            total_documents = cursor.fetchone()[0]

            # Total verifications
            cursor.execute('SELECT COUNT(*) FROM verification_logs')
            total_verifications = cursor.fetchone()[0]

            return {
                'total_users': total_users,
                'total_documents': total_documents,
                'total_verifications': total_verifications
            }

    def get_user_dashboard_data(self, user_id: int) -> Dict[str, Any]:
        """
        Get comprehensive dashboard data for a specific user.
        :return: Dictionary of dashboard data.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            dashboard_data = {}

            # User's personal statistics
            cursor.execute('SELECT COUNT(*) FROM signed_documents WHERE user_id = ?', (user_id,))
            dashboard_data['documents_signed'] = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM verification_logs vl JOIN signed_documents sd ON vl.document_id = sd.id WHERE sd.user_id = ?', (user_id,))
            dashboard_data['documents_verified'] = cursor.fetchone()[0]

            # Recent activity (last 10 documents)
            cursor.execute('''
                SELECT document_name, signed_at, verification_count
                FROM signed_documents
                WHERE user_id = ?
                ORDER BY signed_at DESC
                LIMIT 10
            ''', (user_id,))
            dashboard_data['recent_documents'] = cursor.fetchall()

            # Monthly signing activity (last 12 months)
            cursor.execute('''
                SELECT strftime('%Y-%m', signed_at) as month, COUNT(*) as count
                FROM signed_documents
                WHERE user_id = ? AND signed_at >= date('now', '-12 months')
                GROUP BY strftime('%Y-%m', signed_at)
                ORDER BY month DESC
            ''', (user_id,))
            dashboard_data['monthly_activity'] = cursor.fetchall()

            # Document verification statistics
            cursor.execute('''
                SELECT
                    SUM(verification_count) as total_verifications,
                    AVG(verification_count) as avg_verifications,
                    MAX(verification_count) as max_verifications
                FROM signed_documents
                WHERE user_id = ?
            ''', (user_id,))
            verification_stats = cursor.fetchone()
            dashboard_data['verification_stats'] = {
                'total': verification_stats[0] or 0,
                'average': round(verification_stats[1] or 0, 2),
                'max': verification_stats[2] or 0
            }

            # Certificate information
            cursor.execute('''
                SELECT serial_number, subject_name, valid_from, valid_until, is_revoked
                FROM certificates
                WHERE user_id = ? AND is_revoked = 0
                ORDER BY created_at DESC
                LIMIT 1
            ''', (user_id,))
            cert_info = cursor.fetchone()
            if cert_info:
                dashboard_data['certificate'] = {
                    'serial_number': cert_info[0],
                    'subject_name': cert_info[1],
                    'valid_from': cert_info[2],
                    'valid_until': cert_info[3],
                    'is_revoked': cert_info[4]
                }

            # Recent audit activity
            cursor.execute('''
                SELECT action, details, timestamp
                FROM audit_log
                WHERE user_id = ?
                ORDER BY timestamp DESC
                LIMIT 5
            ''', (user_id,))
            dashboard_data['recent_activity'] = cursor.fetchall()

            return dashboard_data

    def get_recent_documents(self, user_id: int, limit: int = 10) -> List[Tuple[Any, ...]]:
        """
        Get recent documents for quick access.
        :param user_id: The user's database ID.
        :param limit: Number of documents to retrieve.
        :return: List of document tuples.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, document_name, document_path, signed_at, verification_count, category, is_favorite
                FROM signed_documents
                WHERE user_id = ?
                ORDER BY signed_at DESC
                LIMIT ?
            ''', (user_id, limit))
            return cursor.fetchall()

    def get_favorite_documents(self, user_id: int) -> List[Tuple[Any, ...]]:
        """
        Get user's favorite documents.
        :param user_id: The user's database ID.
        :return: List of document tuples.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, document_name, document_path, signed_at, verification_count, category
                FROM signed_documents
                WHERE user_id = ? AND is_favorite = 1
                ORDER BY signed_at DESC
            ''', (user_id,))
            return cursor.fetchall()

    def toggle_document_favorite(self, document_id: int) -> None:
        """
        Toggle favorite status of a document.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE signed_documents
                SET is_favorite = CASE WHEN is_favorite = 1 THEN 0 ELSE 1 END
                WHERE id = ?
            ''', (document_id,))
            conn.commit()

    def get_document_categories(self, user_id: int) -> List[Tuple[str, int]]:
        """
        Get all categories used by a user.
        :param user_id: The user's database ID.
        :return: List of category tuples.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT DISTINCT category, COUNT(*) as count
                FROM signed_documents
                WHERE user_id = ?
                GROUP BY category
                ORDER BY count DESC
            ''', (user_id,))
            return cursor.fetchall()

    def get_documents_by_category(self, user_id: int, category: str) -> List[Tuple[Any, ...]]:
        """
        Get documents by category.
        :param user_id: The user's database ID.
        :param category: The category name.
        :return: List of document tuples.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, document_name, document_path, signed_at, verification_count, is_favorite
                FROM signed_documents
                WHERE user_id = ? AND category = ?
                ORDER BY signed_at DESC
            ''', (user_id, category))
            return cursor.fetchall()

    def update_document_metadata(self, document_id: int, category: Optional[str] = None, tags: Optional[str] = None, notes: Optional[str] = None) -> None:
        """
        Update document metadata.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            updates = []
            params = []

            if category is not None:
                updates.append("category = ?")
                params.append(category)
            if tags is not None:
                updates.append("tags = ?")
                params.append(tags)
            if notes is not None:
                updates.append("notes = ?")
                params.append(notes)

            if updates:
                params.append(document_id)
                cursor.execute(f'''
                    UPDATE signed_documents
                    SET {", ".join(updates)}
                    WHERE id = ?
                ''', params)
                conn.commit()

    def search_documents(self, user_id: int, search_term: str) -> List[Tuple[Any, ...]]:
        """
        Search documents by name, category, tags, or notes.
        :param user_id: The user's database ID.
        :param search_term: The search term.
        :return: List of document tuples.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, document_name, document_path, signed_at, verification_count, category, is_favorite
                FROM signed_documents
                WHERE user_id = ? AND (
                    document_name LIKE ? OR
                    category LIKE ? OR
                    tags LIKE ? OR
                    notes LIKE ?
                )
                ORDER BY signed_at DESC
            ''', (user_id, f'%{search_term}%', f'%{search_term}%', f'%{search_term}%', f'%{search_term}%'))
            return cursor.fetchall()
    
    def get_user_documents(self, user_id: int) -> List[Tuple[str, str, str, str, int]]:
        """
        Get all documents signed by a user.
        :param user_id: The user's database ID.
        :return: List of document tuples.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT document_name, document_path, signature_path, signed_at, verification_count
                FROM signed_documents
                WHERE user_id = ?
                ORDER BY signed_at DESC
            ''', (user_id,))
            return cursor.fetchall()

    def find_document_by_hash(self, document_hash: str) -> Optional[int]:
        """
        Find document ID by hash.
        :param document_hash: The document hash.
        :return: Document ID, or None if not found.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM signed_documents WHERE document_hash = ?', (document_hash,))
            result = cursor.fetchone()
            return result[0] if result else None

    def update_document_verification(self, document_id: int) -> None:
        """
        Update document verification count and timestamp.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE signed_documents
                SET verification_count = verification_count + 1,
                    last_verified = CURRENT_TIMESTAMP,
                    is_verified = 1
                WHERE id = ?
            ''', (document_id,))
            conn.commit()

    def get_document_verification_history(self, document_id: int) -> List[Tuple[str, bool, str, str]]:
        """
        Get verification history for a document.
        :param document_id: The document's database ID.
        :return: List of verification tuples.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT verifier_info, verification_result, verification_details, verified_at
                FROM verification_logs
                WHERE document_id = ?
                ORDER BY verified_at DESC
            ''', (document_id,))
            return cursor.fetchall()

    def get_system_audit_log(self, limit: int = 100) -> List[Tuple[str, str, str, str]]:
        """
        Get recent system audit log entries.
        :param limit: Number of entries to retrieve.
        :return: List of audit tuples.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT u.username, a.action, a.details, a.timestamp
                FROM audit_log a
                LEFT JOIN users u ON a.user_id = u.id
                ORDER BY a.timestamp DESC
                LIMIT ?
            ''', (limit,))
            return cursor.fetchall()

    def get_all_tables_data(self) -> Dict[str, Dict[str, List[Tuple[Any, ...]]]]:
        """
        Get data from all tables for database viewer.
        :return: Dictionary of table data.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            tables_data = {}

            # Get users data
            cursor.execute('SELECT * FROM users')
            tables_data['users'] = {
                'columns': ['id', 'username', 'private_key_path', 'public_key_path', 'certificate_path', 'created_at', 'last_login', 'is_active'],
                'data': cursor.fetchall()
            }

            # Get certificates data
            cursor.execute('SELECT * FROM certificates')
            tables_data['certificates'] = {
                'columns': ['id', 'user_id', 'serial_number', 'subject_name', 'issuer_name', 'valid_from', 'valid_until', 'certificate_path', 'is_revoked', 'created_at'],
                'data': cursor.fetchall()
            }

            # Get signed documents data
            cursor.execute('SELECT * FROM signed_documents')
            tables_data['signed_documents'] = {
                'columns': ['id', 'user_id', 'document_name', 'document_path', 'signature_path', 'document_hash', 'signature_algorithm', 'hash_algorithm', 'signed_at', 'is_verified', 'verification_count', 'last_verified'],
                'data': cursor.fetchall()
            }

            # Get verification logs data
            cursor.execute('SELECT * FROM verification_logs')
            tables_data['verification_logs'] = {
                'columns': ['id', 'document_id', 'verifier_info', 'verification_result', 'verification_details', 'verified_at'],
                'data': cursor.fetchall()
            }

            # Get audit log data
            cursor.execute('SELECT * FROM audit_log')
            tables_data['audit_log'] = {
                'columns': ['id', 'user_id', 'action', 'details', 'ip_address', 'user_agent', 'timestamp'],
                'data': cursor.fetchall()
            }

            return tables_data

    def get_certificate_info(self, user_id: int) -> Optional[Tuple[Any, ...]]:
        """
        Get certificate information for a user.
        :param user_id: The user's database ID.
        :return: Certificate row as a tuple, or None if not found.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT serial_number, subject_name, valid_from, valid_until, is_revoked
                FROM certificates
                WHERE user_id = ? AND is_revoked = 0
                ORDER BY created_at DESC
                LIMIT 1
            ''', (user_id,))
            return cursor.fetchone()

    def revoke_certificate(self, user_id: int, reason: str = "User requested") -> None:
        """
        Revoke a user's certificate.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE certificates
                SET is_revoked = 1
                WHERE user_id = ? AND is_revoked = 0
            ''', (user_id,))
            conn.commit()

            # Log revocation
            cursor.execute('''
                INSERT INTO audit_log (user_id, action, details)
                VALUES (?, ?, ?)
            ''', (user_id, "CERTIFICATE_REVOKED", reason))
            conn.commit()

# =====================
# Main PKI System Class
# =====================

class PKISystem:
    """
    Main application class for Signetrix. Handles all UI, cryptographic, and business logic.
    """
    def __init__(self, root: tk.Tk) -> None:
        """
        Initialize the PKI system, set up CA, database, and main UI.
        :param root: The main Tkinter root window.
        """
        self.root = root
        self.current_user: Optional[str] = None
        self.current_user_id: Optional[int] = None
        self.is_logged_in: bool = False
        self.private_key_path: Optional[str] = None
        self.certificate_path: Optional[str] = None
        # CA management
        self.ca_dir = 'ca'
        self.ca_private_key_path = os.path.join(self.ca_dir, 'ca_private.pem')
        self.ca_cert_path = os.path.join(self.ca_dir, 'ca_cert.pem')
        self.ca_private_key = None
        self.ca_cert = None
        # Initialize database
        self.db = DatabaseManager()
        # Ensure directories exist
        self.ensure_directories()
        # Ensure CA exists
        self.ensure_ca()
        # Setup UI
        self.setup_ui()
        # Update status
        self.update_system_status()
    
    def ensure_directories(self) -> None:
        """
        Create necessary directories if they don't exist (keys, certs, signed_docs, ca, challenge).
        """
        directories = ['keys', 'certs', 'signed_docs', 'ca', 'challenge']
        for directory in directories:
            if not os.path.exists(directory):
                os.makedirs(directory)
    
    def ensure_ca(self) -> None:
        """
        Ensure CA key and certificate exist, generate if missing, and load them.
        """
        if not os.path.exists(self.ca_private_key_path) or not os.path.exists(self.ca_cert_path):
            # Generate CA key
            ca_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            ca_subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Signetrix CA"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Signetrix Root CA"),
            ])
            ca_cert = x509.CertificateBuilder().subject_name(
                ca_subject
            ).issuer_name(
                ca_subject
            ).public_key(
                ca_private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.now(timezone.utc)
            ).not_valid_after(
                datetime.now(timezone.utc) + timedelta(days=3650)
            ).add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            ).sign(ca_private_key, hashes.SHA256())
            # Save CA private key
            with open(self.ca_private_key_path, "wb") as f:
                f.write(ca_private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            # Save CA certificate
            with open(self.ca_cert_path, "wb") as f:
                f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
        # Load CA key and cert
        with open(self.ca_private_key_path, "rb") as f:
            self.ca_private_key = load_pem_private_key(f.read(), password=None)
        with open(self.ca_cert_path, "rb") as f:
            self.ca_cert = x509.load_pem_x509_certificate(f.read())
    
    def setup_ui(self) -> None:
        """
        Set up the main interface with professional styling and responsive design.
        """
        # Window configuration with responsive sizing
        self.root.title("Signetrix - Professional Edition")
        self.root.geometry("1400x900")
        self.root.minsize(800, 600)  # Reduced minimum size for better responsiveness
        self.root.configure(bg=Colors.BG_MAIN)

        # Configure window icon and styling
        try:
            self.root.state('zoomed')  # Maximize on Windows
        except:
            pass

        # Configure modern styling
        self.configure_styles()

        # Create main container with scrollable content
        self.create_main_container()

        # Create header
        self.create_header()

        # Create main content area
        self.create_main_content()

        # Create status bar
        self.create_status_bar()

        # Add smooth animations
        self.setup_animations()

        # Setup responsive behavior
        self.setup_responsive_design()

    def setup_responsive_design(self) -> None:
        """
        Set up responsive design behaviors (window resize bindings, etc).
        """
        # Bind window resize events
        self.root.bind('<Configure>', self.on_window_resize)

        # Store initial window size for responsive calculations
        self.root.update_idletasks()
        self.initial_width = self.root.winfo_width()
        self.initial_height = self.root.winfo_height()

    def on_window_resize(self, event: tk.Event) -> None:
        """
        Handle window resize events for responsive design.
        """
        # Only handle main window resize events
        if event.widget == self.root:
            current_width = event.width
            current_height = event.height

            # Adjust component sizes based on window size
            self.adjust_responsive_layout(current_width, current_height)

    def adjust_responsive_layout(self, width: int, height: int) -> None:
        """
        Adjust layout based on window size.
        """
        # Calculate responsive padding based on window width
        if width < 1000:
            # Small screen - reduce padding
            section_padx = 10
            content_padx = 15
            header_padx = 10
        elif width < 1300:
            # Medium screen - moderate padding
            section_padx = 15
            content_padx = 20
            header_padx = 15
        else:
            # Large screen - full padding
            section_padx = 20
            content_padx = 25
            header_padx = 20

        # Update section padding dynamically
        try:
            # Update content frame padding
            if hasattr(self, 'content_frame'):
                self.content_frame.pack_configure(padx=content_padx)
        except:
            pass

    def configure_styles(self) -> None:
        """
        Configure modern TTK styles for the UI.
        """
        style = ttk.Style()

        # Configure modern button style
        style.configure('Modern.TButton',
                       font=(Fonts.PRIMARY, Fonts.BODY, 'bold'),
                       padding=(20, 10))

        # Configure modern frame style
        style.configure('Card.TFrame',
                       background=Colors.BG_CARD,
                       relief='flat',
                       borderwidth=1)

    def setup_animations(self) -> None:
        """
        Set up smooth animations and transitions (e.g., fade-in).
        """
        # Add fade-in effect for the main window
        self.root.attributes('-alpha', 0.0)
        self.fade_in_window()

    def fade_in_window(self) -> None:
        """
        Smooth fade-in animation for the main window.
        """
        alpha = self.root.attributes('-alpha')
        if alpha < 1.0:
            alpha += 0.05
            self.root.attributes('-alpha', alpha)
            self.root.after(20, self.fade_in_window)
    
    def create_main_container(self) -> None:
        """
        Create modern scrollable main container.
        """
        # Main frame with modern background
        self.main_frame = tk.Frame(self.root, bg=Colors.BG_MAIN)
        self.main_frame.pack(fill='both', expand=True, padx=2, pady=2)

        # Create modern canvas with custom styling
        self.canvas = tk.Canvas(self.main_frame,
                               bg=Colors.BG_MAIN,
                               highlightthickness=0,
                               bd=0)

        # Custom styled scrollbar
        self.scrollbar = tk.Scrollbar(self.main_frame,
                                     orient="vertical",
                                     command=self.canvas.yview,
                                     bg=Colors.BG_SIDEBAR,
                                     troughcolor=Colors.BG_MAIN,
                                     activebackground=Colors.BUTTON_HOVER,
                                     width=12)

        self.scrollable_frame = tk.Frame(self.canvas, bg=Colors.BG_MAIN)

        # Configure scrolling
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )

        self.canvas_window = self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        # Bind canvas resize event
        self.canvas.bind("<Configure>", self._on_canvas_configure)

        # Pack with modern layout
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        # Enhanced mouse wheel binding
        self.canvas.bind("<MouseWheel>", self._on_mousewheel)
        self.root.bind("<MouseWheel>", self._on_mousewheel)
    
    def _on_mousewheel(self, event: tk.Event) -> None:
        """
        Handle mouse wheel scrolling.
        """
        self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")

    def _on_canvas_configure(self, event: tk.Event) -> None:
        """
        Handle canvas resize to update scroll region and width.
        """
        # Update the canvas scroll region when the frame changes size
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

        # Update the canvas window width to match the canvas width
        canvas_width = event.width
        self.canvas.itemconfig(self.canvas_window, width=canvas_width)
    
    def create_header(self) -> None:
        """
        Create modern responsive professional header.
        """
        # Get responsive sizing
        window_width = self.root.winfo_width() if self.root.winfo_width() > 1 else 1400

        if window_width < 1000:
            header_height = 80
            header_padx = 10
            icon_size = 24
            title_size = Fonts.HEADING
        elif window_width < 1300:
            header_height = 90
            header_padx = 15
            icon_size = 28
            title_size = Fonts.TITLE - 2
        else:
            header_height = 100
            header_padx = 20
            icon_size = 32
            title_size = Fonts.TITLE

        # Main header container with gradient effect
        header_container = tk.Frame(self.scrollable_frame, bg=Colors.BG_MAIN)
        header_container.pack(fill='x', padx=0, pady=(20, 10))

        # Header card with shadow effect - responsive height
        header_frame = tk.Frame(header_container, bg=Colors.PRIMARY_DARK,
                               relief='flat', bd=0, height=header_height)
        header_frame.pack(fill='x', padx=header_padx)
        header_frame.pack_propagate(False)

        # Add subtle shadow effect
        shadow_frame = tk.Frame(header_container, bg=Colors.BORDER_MEDIUM, height=2)
        shadow_frame.pack(fill='x')

        # Left side - Modern title section
        left_frame = tk.Frame(header_frame, bg=Colors.PRIMARY_DARK)
        left_frame.pack(side='left', fill='y', padx=30, pady=15)

        # Icon and title container
        title_container = tk.Frame(left_frame, bg=Colors.PRIMARY_DARK)
        title_container.pack(anchor='w')

        # Responsive icon
        icon_label = tk.Label(title_container, text="🔐",
                             font=(Fonts.PRIMARY, icon_size),
                             fg=Colors.TEXT_WHITE, bg=Colors.PRIMARY_DARK)
        icon_label.pack(side='left', padx=(0, 15))

        # Title and subtitle
        text_container = tk.Frame(title_container, bg=Colors.PRIMARY_DARK)
        text_container.pack(side='left', fill='y')

        # Responsive title
        title_text = "Signetrix" if window_width >= 1000 else "Signetrix"
        title_label = tk.Label(text_container, text=title_text,
                              font=(Fonts.PRIMARY, title_size, 'bold'),
                              fg=Colors.TEXT_WHITE, bg=Colors.PRIMARY_DARK)
        title_label.pack(anchor='w')

        # Responsive subtitle
        if window_width >= 1000:
            subtitle_text = "Professional Digital Authentication Platform"
            subtitle_label = tk.Label(text_container, text=subtitle_text,
                                     font=(Fonts.PRIMARY, Fonts.BODY),
                                     fg=Colors.TEXT_LIGHT, bg=Colors.PRIMARY_DARK)
            subtitle_label.pack(anchor='w')

        # Right side - Modern user status and help button
        right_frame = tk.Frame(header_frame, bg=Colors.PRIMARY_DARK)
        right_frame.pack(side='right', fill='y', padx=30, pady=15)

        # Help button (question mark)
        help_btn = tk.Button(right_frame, text="?", font=(Fonts.PRIMARY, 18, 'bold'),
                            bg=Colors.BUTTON_PRIMARY, fg=Colors.TEXT_WHITE, relief='flat', bd=0,
                            activebackground=Colors.INFO, activeforeground=Colors.TEXT_WHITE,
                            width=2, height=1, cursor='hand2',
                            command=self.show_use_case_window)
        help_btn.pack(side='right', padx=(0, 10))

        # Status container
        status_container = tk.Frame(right_frame, bg=Colors.PRIMARY_DARK)
        status_container.pack(anchor='e')

        self.user_status_label = tk.Label(status_container, text="● Not Logged In",
                                         font=(Fonts.PRIMARY, Fonts.SUBHEADING, 'bold'),
                                         fg=Colors.ERROR, bg=Colors.PRIMARY_DARK)
        self.user_status_label.pack(anchor='e')

        self.user_info_label = tk.Label(status_container, text="Please login to access all features",
                                       font=(Fonts.PRIMARY, Fonts.SMALL),
                                       fg=Colors.TEXT_LIGHT, bg=Colors.PRIMARY_DARK)
        self.user_info_label.pack(anchor='e')
    
    def create_main_content(self) -> None:
        """
        Create the main content area with dynamic sections based on login state.
        """
        self.content_frame = tk.Frame(self.scrollable_frame, bg='#f0f0f0')
        self.content_frame.pack(fill='both', expand=True, padx=0, pady=10)

        # Create initial UI (before login)
        self.create_initial_ui()

    def create_initial_ui(self) -> None:
        """
        Create the initial UI before login.
        """
        # Clear existing content
        for widget in self.content_frame.winfo_children():
            widget.destroy()

        # Create sections for non-authenticated users
        self.create_registration_section(self.content_frame)
        self.create_login_section(self.content_frame)
        self.create_verification_section(self.content_frame)

    def create_user_ui(self) -> None:
        """
        Create a new, clean, professional dashboard UI after login.
        """
        # Clear existing content
        for widget in self.content_frame.winfo_children():
            widget.destroy()

        # Main dashboard frame
        dashboard = tk.Frame(self.content_frame, bg=Colors.BG_MAIN)
        dashboard.pack(fill='both', expand=True)

        # Header
        header = tk.Frame(dashboard, bg=Colors.PRIMARY_DARK, height=80)
        header.pack(fill='x', pady=(0, 20), padx=20)
        header.pack_propagate(False)
        tk.Label(header, text=f"Welcome to Signetrix, {self.current_user}!",
                 font=(Fonts.PRIMARY, Fonts.TITLE, 'bold'),
                 fg=Colors.TEXT_WHITE, bg=Colors.PRIMARY_DARK).pack(side='left', padx=20, pady=20)
        tk.Button(header, text="Logout", command=self.perform_logout,
                  font=(Fonts.PRIMARY, Fonts.BODY, 'bold'),
                  bg=Colors.ERROR, fg=Colors.TEXT_WHITE, relief='flat', bd=0,
                  activebackground=Colors.BUTTON_DANGER, activeforeground=Colors.TEXT_WHITE,
                  padx=20, pady=10, cursor='hand2').pack(side='right', padx=20, pady=20)

        # Main content area (centered)
        content = tk.Frame(dashboard, bg=Colors.BG_MAIN)
        content.pack(expand=True)

        # Document Signing Section
        sign_frame = tk.Frame(content, bg=Colors.BG_CARD, relief='flat', bd=1)
        sign_frame.pack(pady=20, ipadx=20, ipady=20, fill='x', expand=True)
        tk.Label(sign_frame, text="✍️ Document Signing",
                 font=(Fonts.PRIMARY, Fonts.HEADING, 'bold'),
                 fg=Colors.TEXT_PRIMARY, bg=Colors.BG_CARD).pack(anchor='w', padx=20, pady=(20, 5))
        tk.Label(sign_frame, text="Sign a document with your digital signature.",
                 font=(Fonts.PRIMARY, Fonts.BODY), fg=Colors.TEXT_SECONDARY, bg=Colors.BG_CARD).pack(anchor='w', padx=20)
        sign_btn = tk.Button(sign_frame, text="Sign Document", command=lambda: self.show_sign_section(content),
                             font=(Fonts.PRIMARY, Fonts.BODY, 'bold'),
                             bg=Colors.BUTTON_SUCCESS, fg=Colors.TEXT_WHITE, relief='flat', bd=0,
                             activebackground=Colors.SUCCESS, activeforeground=Colors.TEXT_WHITE,
                             padx=20, pady=10, cursor='hand2')
        sign_btn.pack(anchor='w', padx=20, pady=20)

        # Document Verification Section
        verify_frame = tk.Frame(content, bg=Colors.BG_CARD, relief='flat', bd=1)
        verify_frame.pack(pady=20, ipadx=20, ipady=20, fill='x', expand=True)
        tk.Label(verify_frame, text="✅ Document Verification",
                 font=(Fonts.PRIMARY, Fonts.HEADING, 'bold'),
                 fg=Colors.TEXT_PRIMARY, bg=Colors.BG_CARD).pack(anchor='w', padx=20, pady=(20, 5))
        tk.Label(verify_frame, text="Verify the authenticity of a signed document.",
                 font=(Fonts.PRIMARY, Fonts.BODY), fg=Colors.TEXT_SECONDARY, bg=Colors.BG_CARD).pack(anchor='w', padx=20)
        verify_btn = tk.Button(verify_frame, text="Verify Document", command=lambda: self.show_verify_section(content),
                               font=(Fonts.PRIMARY, Fonts.BODY, 'bold'),
                               bg=Colors.BUTTON_PRIMARY, fg=Colors.TEXT_WHITE, relief='flat', bd=0,
                               activebackground=Colors.INFO, activeforeground=Colors.TEXT_WHITE,
                               padx=20, pady=10, cursor='hand2')
        verify_btn.pack(anchor='w', padx=20, pady=20)

        # Settings Section (Change Password)
        settings_frame = tk.Frame(content, bg=Colors.BG_CARD, relief='flat', bd=1)
        settings_frame.pack(pady=20, ipadx=20, ipady=20, fill='x', expand=True)
        tk.Label(settings_frame, text="⚙️ Settings",
                 font=(Fonts.PRIMARY, Fonts.HEADING, 'bold'),
                 fg=Colors.TEXT_PRIMARY, bg=Colors.BG_CARD).pack(anchor='w', padx=20, pady=(20, 5))
        tk.Label(settings_frame, text="Change your account password.",
                 font=(Fonts.PRIMARY, Fonts.BODY), fg=Colors.TEXT_SECONDARY, bg=Colors.BG_CARD).pack(anchor='w', padx=20)
        change_pw_btn = tk.Button(settings_frame, text="Change Password", command=self.show_change_password_modal,
                                  font=(Fonts.PRIMARY, Fonts.BODY, 'bold'),
                                  bg=Colors.BUTTON_WARNING, fg=Colors.TEXT_WHITE, relief='flat', bd=0,
                                  activebackground=Colors.WARNING, activeforeground=Colors.TEXT_WHITE,
                                  padx=20, pady=10, cursor='hand2')
        change_pw_btn.pack(anchor='w', padx=20, pady=20)

    def show_change_password_modal(self) -> None:
        """
        Show a modal window for changing the user's password.
        """
        modal = tk.Toplevel(self.root)
        modal.title("Change Password - Signetrix")
        modal.geometry("400x400")  # Increased height for extra space
        modal.resizable(False, False)
        modal.configure(bg=Colors.BG_MAIN)
        modal.transient(self.root)
        modal.grab_set()
        tk.Label(modal, text="Change Password", font=(Fonts.PRIMARY, Fonts.HEADING, 'bold'), fg=Colors.TEXT_PRIMARY, bg=Colors.BG_MAIN).pack(pady=(30, 10))
        form = tk.Frame(modal, bg=Colors.BG_MAIN)
        form.pack(pady=10, padx=30, fill='x')
        tk.Label(form, text="Current Password:", font=(Fonts.PRIMARY, Fonts.BODY, 'bold'), fg=Colors.TEXT_PRIMARY, bg=Colors.BG_MAIN).pack(anchor='w', pady=(0, 2))
        current_pw = tk.Entry(form, show='*', font=(Fonts.PRIMARY, Fonts.BODY), width=25, relief='flat', bd=1, bg=Colors.BG_CARD, fg=Colors.TEXT_PRIMARY)
        current_pw.pack(fill='x', pady=(0, 10))
        tk.Label(form, text="New Password:", font=(Fonts.PRIMARY, Fonts.BODY, 'bold'), fg=Colors.TEXT_PRIMARY, bg=Colors.BG_MAIN).pack(anchor='w', pady=(0, 2))
        new_pw = tk.Entry(form, show='*', font=(Fonts.PRIMARY, Fonts.BODY), width=25, relief='flat', bd=1, bg=Colors.BG_CARD, fg=Colors.TEXT_PRIMARY)
        new_pw.pack(fill='x', pady=(0, 10))
        tk.Label(form, text="Confirm New Password:", font=(Fonts.PRIMARY, Fonts.BODY, 'bold'), fg=Colors.TEXT_PRIMARY, bg=Colors.BG_MAIN).pack(anchor='w', pady=(0, 2))
        confirm_pw = tk.Entry(form, show='*', font=(Fonts.PRIMARY, Fonts.BODY), width=25, relief='flat', bd=1, bg=Colors.BG_CARD, fg=Colors.TEXT_PRIMARY)
        confirm_pw.pack(fill='x', pady=(0, 10))
        status_label = tk.Label(modal, text="", font=(Fonts.PRIMARY, Fonts.BODY), bg=Colors.BG_MAIN)
        status_label.pack(pady=(5, 0))
        def change_password():
            curr = current_pw.get().strip()
            new = new_pw.get().strip()
            conf = confirm_pw.get().strip()
            if not curr or not new or not conf:
                status_label.config(text="All fields are required.", fg=Colors.ERROR)
                return
            valid, msg = self._validate_password_strength(new)
            if not valid:
                status_label.config(text=msg, fg=Colors.ERROR)
                return
            if new != conf:
                status_label.config(text="New passwords do not match.", fg=Colors.ERROR)
                return
            # Fetch user data
            user_data = self.db.get_user_by_username(self.current_user)
            if not user_data:
                status_label.config(text="User not found.", fg=Colors.ERROR)
                return
            password_hash = user_data[8]
            salt = user_data[9]
            curr_hash = hashlib.pbkdf2_hmac('sha256', curr.encode(), salt.encode(), 100_000).hex()
            if curr_hash != password_hash:
                status_label.config(text="Current password is incorrect.", fg=Colors.ERROR)
                return
            # Generate new salt and hash
            new_salt = secrets.token_hex(16)
            new_hash = hashlib.pbkdf2_hmac('sha256', new.encode(), new_salt.encode(), 100_000).hex()
            # Re-encrypt private key with new password
            try:
                with open(self.private_key_path, "rb") as key_file:
                    private_key = load_pem_private_key(key_file.read(), password=curr.encode())
                from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
                with open(self.private_key_path, "wb") as key_file:
                    key_file.write(private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=BestAvailableEncryption(new.encode())
                    ))
            except Exception as e:
                status_label.config(text=f"Failed to re-encrypt private key: {str(e)}", fg=Colors.ERROR)
                return
            # Update in database
            with sqlite3.connect(self.db.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('UPDATE users SET password_hash = ?, salt = ? WHERE username = ?', (new_hash, new_salt, self.current_user))
                conn.commit()
            status_label.config(text="Password changed successfully!", fg=Colors.SUCCESS)
            modal.after(1200, modal.destroy)
            self.db.log_audit_event(self.current_user_id, "PASSWORD_CHANGED", "User changed their password.")
        # Button frame for proper layout
        button_frame = tk.Frame(modal, bg=Colors.BG_MAIN)
        button_frame.pack(pady=20)
        tk.Button(button_frame, text="Change Password", command=change_password, font=(Fonts.PRIMARY, Fonts.BODY, 'bold'), bg=Colors.BUTTON_SUCCESS, fg=Colors.TEXT_WHITE, relief='flat', bd=0, padx=20, pady=10, cursor='hand2').pack(side='left', padx=10)
        tk.Button(button_frame, text="Cancel", command=modal.destroy, font=(Fonts.PRIMARY, Fonts.SMALL), bg=Colors.BUTTON_DANGER, fg=Colors.TEXT_WHITE, relief='flat', bd=0, padx=10, pady=5, cursor='hand2').pack(side='left', padx=10)
        modal.update_idletasks()
        modal.lift()
        modal.focus_force()

    def _validate_password_strength(self, password: str) -> Tuple[bool, str]:
        """
        Check password strength: min 8 chars, upper, lower, digit, special char.
        :param password: The password to check.
        :return: Tuple (valid, message).
        """
        if len(password) < 8:
            return False, "Password must be at least 8 characters."
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter."
        if not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter."
        if not re.search(r'\d', password):
            return False, "Password must contain at least one digit."
        if not re.search(r'[^A-Za-z0-9]', password):
            return False, "Password must contain at least one special character."
        return True, ""

    def show_sign_section(self, parent: tk.Frame) -> None:
        """
        Show the document signing section in a modal-like frame.
        """
        self._clear_content(parent)
        frame = tk.Frame(parent, bg=Colors.BG_CARD, relief='flat', bd=1)
        frame.pack(pady=40, ipadx=20, ipady=20, fill='x', expand=True)
        tk.Label(frame, text="✍️ Sign a Document", font=(Fonts.PRIMARY, Fonts.HEADING, 'bold'), fg=Colors.TEXT_PRIMARY, bg=Colors.BG_CARD).pack(anchor='w', padx=20, pady=(20, 5))
        tk.Label(frame, text="Select a document to sign:", font=(Fonts.PRIMARY, Fonts.BODY), fg=Colors.TEXT_SECONDARY, bg=Colors.BG_CARD).pack(anchor='w', padx=20)
        doc_path_var = tk.StringVar()
        doc_entry = tk.Entry(frame, textvariable=doc_path_var, font=(Fonts.PRIMARY, Fonts.BODY), width=40, relief='flat', bd=1, bg=Colors.BG_MAIN, fg=Colors.TEXT_PRIMARY)
        doc_entry.pack(anchor='w', padx=20, pady=(10, 0))
        def browse():
            path = filedialog.askopenfilename(title="Select Document", filetypes=[("All files", "*.*")])
            if path:
                doc_path_var.set(path)
        tk.Button(frame, text="Browse", command=browse, font=(Fonts.PRIMARY, Fonts.SMALL), bg=Colors.BUTTON_PRIMARY, fg=Colors.TEXT_WHITE, relief='flat', bd=0, padx=10, pady=5, cursor='hand2').pack(anchor='w', padx=20, pady=(5, 10))
        # Password entry for signing
        tk.Label(frame, text="Password for Private Key:", font=(Fonts.PRIMARY, Fonts.BODY, 'bold'), fg=Colors.TEXT_PRIMARY, bg=Colors.BG_CARD).pack(anchor='w', padx=20, pady=(10, 2))
        sign_pw_entry = tk.Entry(frame, show='*', font=(Fonts.PRIMARY, Fonts.BODY), width=25, relief='flat', bd=1, bg=Colors.BG_MAIN, fg=Colors.TEXT_PRIMARY)
        sign_pw_entry.pack(anchor='w', padx=20, pady=(0, 10))
        status_label = tk.Label(frame, text="", font=(Fonts.PRIMARY, Fonts.BODY), bg=Colors.BG_CARD)
        status_label.pack(anchor='w', padx=20, pady=(5, 0))
        def sign():
            path = doc_path_var.get()
            password = sign_pw_entry.get()
            if not path:
                status_label.config(text="Please select a document.", fg=Colors.ERROR)
                return
            if not password:
                status_label.config(text="Please enter your password.", fg=Colors.ERROR)
                return
            self.document_path = path
            self.sign_document(status_label=status_label, password=password)
        tk.Button(frame, text="Sign", command=sign, font=(Fonts.PRIMARY, Fonts.BODY, 'bold'), bg=Colors.BUTTON_SUCCESS, fg=Colors.TEXT_WHITE, relief='flat', bd=0, padx=20, pady=10, cursor='hand2').pack(anchor='w', padx=20, pady=20)
        tk.Button(frame, text="Back", command=lambda: self.create_user_ui(), font=(Fonts.PRIMARY, Fonts.SMALL), bg=Colors.BUTTON_DANGER, fg=Colors.TEXT_WHITE, relief='flat', bd=0, padx=10, pady=5, cursor='hand2').pack(anchor='w', padx=20, pady=(5, 10))

    def sign_document(self, status_label: Optional[tk.Label] = None, password: Optional[str] = None) -> None:
        """
        Sign the selected document with database integration (supports modal feedback, decrypt private key).
        """
        if not hasattr(self, 'document_path') or not self.document_path:
            if status_label:
                status_label.config(text="Please select a document to sign!", fg=Colors.ERROR)
            else:
                messagebox.showerror("Error", "Please select a document to sign!")
            return
        try:
            if status_label:
                status_label.config(text="Signing document...", fg=Colors.WARNING)
            else:
                self.sign_status_label.config(text="Signing document...", fg=Colors.WARNING)
            self.root.update()
            # Read the document
            with open(self.document_path, 'rb') as f:
                document_data = f.read()
            document_hash = hashlib.sha256(document_data).hexdigest()
            # Prompt for password to decrypt private key
            if password is None:
                password = ''
            with open(self.private_key_path, "rb") as key_file:
                private_key = load_pem_private_key(key_file.read(), password=password.encode())
            signature = private_key.sign(
                document_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            doc_name = os.path.basename(self.document_path)
            signed_doc_path = f"signed_docs/{doc_name}"
            signature_path = f"signed_docs/{doc_name}.sig"
            cert_copy_path = f"signed_docs/{doc_name}_cert.pem"
            with open(self.document_path, 'rb') as src, open(signed_doc_path, 'wb') as dst:
                dst.write(src.read())
            with open(signature_path, 'wb') as f:
                f.write(signature)
            with open(self.certificate_path, 'rb') as src, open(cert_copy_path, 'wb') as dst:
                dst.write(src.read())
            document_id = self.db.add_signed_document(
                user_id=self.current_user_id,
                document_name=doc_name,
                document_path=signed_doc_path,
                signature_path=signature_path,
                document_hash=document_hash
            )
            self.db.log_audit_event(
                self.current_user_id,
                "DOCUMENT_SIGNED",
                f"Document '{doc_name}' signed successfully (ID: {document_id})"
            )
            if status_label:
                status_label.config(text="✓ Document signed successfully!", fg=Colors.SUCCESS)
            else:
                self.sign_status_label.config(text=f"✓ Document signed successfully!", fg=Colors.SUCCESS)
            self.update_system_status()
            messagebox.showinfo("Success",
                              f"Document signed successfully!\n\n"
                              f"Files created:\n"
                              f"• {signed_doc_path}\n"
                              f"• {signature_path}\n"
                              f"• {cert_copy_path}\n\n"
                              f"Document ID: {document_id}\n"
                              f"Use these files for verification.")
        except Exception as e:
            if status_label:
                status_label.config(text=f"Signing failed: {str(e)}", fg=Colors.ERROR)
            else:
                self.sign_status_label.config(text=f"Signing failed: {str(e)}", fg=Colors.ERROR)
            messagebox.showerror("Error", f"Document signing failed: {str(e)}")
            if hasattr(self, 'current_user_id') and self.current_user_id:
                self.db.log_audit_event(
                    self.current_user_id,
                    "DOCUMENT_SIGN_FAILED",
                    f"Failed to sign document: {str(e)}"
                )

    def show_verify_section(self, parent: tk.Frame) -> None:
        """
        Show the document verification section in a modal-like frame.
        """
        self._clear_content(parent)
        frame = tk.Frame(parent, bg=Colors.BG_CARD, relief='flat', bd=1)
        frame.pack(pady=40, ipadx=20, ipady=20, fill='x', expand=True)
        tk.Label(frame, text="✅ Verify a Document", font=(Fonts.PRIMARY, Fonts.HEADING, 'bold'), fg=Colors.TEXT_PRIMARY, bg=Colors.BG_CARD).pack(anchor='w', padx=20, pady=(20, 5))
        tk.Label(frame, text="Select the original document and signature file:", font=(Fonts.PRIMARY, Fonts.BODY), fg=Colors.TEXT_SECONDARY, bg=Colors.BG_CARD).pack(anchor='w', padx=20)
        doc_path_var = tk.StringVar()
        sig_path_var = tk.StringVar()
        cert_path_var = tk.StringVar()
        tk.Label(frame, text="Document:", font=(Fonts.PRIMARY, Fonts.BODY, 'bold'), fg=Colors.TEXT_PRIMARY, bg=Colors.BG_CARD).pack(anchor='w', padx=20, pady=(10, 0))
        doc_entry = tk.Entry(frame, textvariable=doc_path_var, font=(Fonts.PRIMARY, Fonts.BODY), width=40, relief='flat', bd=1, bg=Colors.BG_MAIN, fg=Colors.TEXT_PRIMARY)
        doc_entry.pack(anchor='w', padx=20, pady=(0, 0))
        def browse_doc():
            path = filedialog.askopenfilename(title="Select Document", filetypes=[("All files", "*.*")])
            if path:
                doc_path_var.set(path)
        tk.Button(frame, text="Browse", command=browse_doc, font=(Fonts.PRIMARY, Fonts.SMALL), bg=Colors.BUTTON_PRIMARY, fg=Colors.TEXT_WHITE, relief='flat', bd=0, padx=10, pady=5, cursor='hand2').pack(anchor='w', padx=20, pady=(5, 10))
        tk.Label(frame, text="Signature File:", font=(Fonts.PRIMARY, Fonts.BODY, 'bold'), fg=Colors.TEXT_PRIMARY, bg=Colors.BG_CARD).pack(anchor='w', padx=20, pady=(10, 0))
        sig_entry = tk.Entry(frame, textvariable=sig_path_var, font=(Fonts.PRIMARY, Fonts.BODY), width=40, relief='flat', bd=1, bg=Colors.BG_MAIN, fg=Colors.TEXT_PRIMARY)
        sig_entry.pack(anchor='w', padx=20, pady=(0, 0))
        def browse_sig():
            path = filedialog.askopenfilename(title="Select Signature File", filetypes=[("Signature files", "*.sig"), ("All files", "*.*")])
            if path:
                sig_path_var.set(path)
        tk.Button(frame, text="Browse", command=browse_sig, font=(Fonts.PRIMARY, Fonts.SMALL), bg=Colors.BUTTON_PRIMARY, fg=Colors.TEXT_WHITE, relief='flat', bd=0, padx=10, pady=5, cursor='hand2').pack(anchor='w', padx=20, pady=(5, 10))
        tk.Label(frame, text="Certificate File:", font=(Fonts.PRIMARY, Fonts.BODY, 'bold'), fg=Colors.TEXT_PRIMARY, bg=Colors.BG_CARD).pack(anchor='w', padx=20, pady=(10, 0))
        cert_entry = tk.Entry(frame, textvariable=cert_path_var, font=(Fonts.PRIMARY, Fonts.BODY), width=40, relief='flat', bd=1, bg=Colors.BG_MAIN, fg=Colors.TEXT_PRIMARY)
        cert_entry.pack(anchor='w', padx=20, pady=(0, 0))
        def browse_cert():
            path = filedialog.askopenfilename(title="Select Certificate File", filetypes=[("PEM files", "*.pem"), ("All files", "*.*")])
            if path:
                cert_path_var.set(path)
        tk.Button(frame, text="Browse", command=browse_cert, font=(Fonts.PRIMARY, Fonts.SMALL), bg=Colors.BUTTON_PRIMARY, fg=Colors.TEXT_WHITE, relief='flat', bd=0, padx=10, pady=5, cursor='hand2').pack(anchor='w', padx=20, pady=(5, 10))
        status_label = tk.Label(frame, text="", font=(Fonts.PRIMARY, Fonts.BODY), bg=Colors.BG_CARD)
        status_label.pack(anchor='w', padx=20, pady=(5, 0))
        def verify():
            doc = doc_path_var.get()
            sig = sig_path_var.get()
            cert = cert_path_var.get()
            if not doc or not sig or not cert:
                status_label.config(text="Please select all files.", fg=Colors.ERROR)
                return
            self.orig_document_path = doc
            self.signature_file_path = sig
            self.cert_verify_path = cert
            self.verify_document()
            status_label.config(text="Verification complete!", fg=Colors.SUCCESS)
        tk.Button(frame, text="Verify", command=verify, font=(Fonts.PRIMARY, Fonts.BODY, 'bold'), bg=Colors.BUTTON_PRIMARY, fg=Colors.TEXT_WHITE, relief='flat', bd=0, padx=20, pady=10, cursor='hand2').pack(anchor='w', padx=20, pady=20)
        tk.Button(frame, text="Back", command=lambda: self.create_user_ui(), font=(Fonts.PRIMARY, Fonts.SMALL), bg=Colors.BUTTON_DANGER, fg=Colors.TEXT_WHITE, relief='flat', bd=0, padx=10, pady=5, cursor='hand2').pack(anchor='w', padx=20, pady=(5, 10))

    def _clear_content(self, parent: tk.Frame) -> None:
        for widget in parent.winfo_children():
            widget.destroy()

    def create_user_tabs(self) -> None:
        """
        Create tabbed interface for user dashboard.
        """
        # Create notebook (tabbed interface)
        self.user_notebook = ttk.Notebook(self.content_frame)
        self.user_notebook.pack(fill='both', expand=True, padx=20, pady=10)

        # Dashboard Tab
        self.dashboard_frame = tk.Frame(self.user_notebook, bg=Colors.BG_MAIN)
        self.user_notebook.add(self.dashboard_frame, text="📊 Dashboard")

        # Documents Tab
        self.documents_frame = tk.Frame(self.user_notebook, bg=Colors.BG_MAIN)
        self.user_notebook.add(self.documents_frame, text="📄 Documents")

        # Settings Tab
        self.settings_frame = tk.Frame(self.user_notebook, bg=Colors.BG_MAIN)
        self.user_notebook.add(self.settings_frame, text="⚙️ Settings")

        # Create content for each tab
        self.create_dashboard_tab()
        self.create_documents_tab()
        self.create_settings_tab()

    def create_dashboard_tab(self) -> None:
        """
        Create the main dashboard with analytics.
        """
        # Create scrollable frame for dashboard
        dashboard_canvas = tk.Canvas(self.dashboard_frame, bg=Colors.BG_MAIN, highlightthickness=0)
        dashboard_scrollbar = ttk.Scrollbar(self.dashboard_frame, orient="vertical", command=dashboard_canvas.yview)
        dashboard_scrollable = tk.Frame(dashboard_canvas, bg=Colors.BG_MAIN)

        dashboard_scrollable.bind(
            "<Configure>",
            lambda e: dashboard_canvas.configure(scrollregion=dashboard_canvas.bbox("all"))
        )

        dashboard_canvas.create_window((0, 0), window=dashboard_scrollable, anchor="nw")
        dashboard_canvas.configure(yscrollcommand=dashboard_scrollbar.set)

        dashboard_canvas.pack(side="left", fill="both", expand=True)
        dashboard_scrollbar.pack(side="right", fill="y")

        # Welcome header
        self.create_dashboard_header(dashboard_scrollable)

        # Statistics cards
        self.create_statistics_cards(dashboard_scrollable)

        # Activity charts
        self.create_activity_charts(dashboard_scrollable)

        # Recent activity
        self.create_recent_activity(dashboard_scrollable)

        # Certificate status
        self.create_certificate_status(dashboard_scrollable)

    def create_dashboard_header(self, parent: tk.Frame) -> None:
        """
        Create dashboard welcome header.
        """
        header_frame = tk.Frame(parent, bg=Colors.PRIMARY_DARK, height=80)
        header_frame.pack(fill='x', pady=(0, 20), padx=20)
        header_frame.pack_propagate(False)

        # Welcome message
        welcome_label = tk.Label(header_frame,
                                text=f"Welcome back, {self.current_user}!",
                                font=(Fonts.PRIMARY, Fonts.TITLE, 'bold'),
                                fg=Colors.TEXT_WHITE, bg=Colors.PRIMARY_DARK)
        welcome_label.pack(expand=True, pady=20)

    def create_statistics_cards(self, parent: tk.Frame) -> None:
        """
        Create statistics cards showing user metrics.
        """
        # Get user dashboard data
        dashboard_data = self.db.get_user_dashboard_data(self.current_user_id)

        # Statistics container
        stats_container = tk.Frame(parent, bg=Colors.BG_MAIN)
        stats_container.pack(fill='x', padx=20, pady=(0, 20))

        # Create individual stat cards
        stats = [
            ("Documents Signed", dashboard_data.get('documents_signed', 0), Colors.SUCCESS, "📄"),
            ("Total Verifications", dashboard_data.get('verification_stats', {}).get('total', 0), Colors.INFO, "✅"),
            ("Average Verifications", dashboard_data.get('verification_stats', {}).get('average', 0), Colors.WARNING, "📊"),
            ("Documents Verified", dashboard_data.get('documents_verified', 0), Colors.LIGHT_BLUE, "🔍")
        ]

        for i, (title, value, color, icon) in enumerate(stats):
            self.create_stat_card(stats_container, title, value, color, icon, i)

    def create_stat_card(self, parent: tk.Frame, title: str, value: int, color: str, icon: str, position: int) -> None:
        """
        Create individual statistics card.
        """
        # Card frame
        card_frame = tk.Frame(parent, bg=Colors.BG_CARD, relief='flat', bd=1)
        card_frame.grid(row=0, column=position, padx=10, pady=10, sticky='nsew')

        # Configure grid weights
        parent.grid_columnconfigure(position, weight=1)

        # Header with color accent
        header_frame = tk.Frame(card_frame, bg=color, height=40)
        header_frame.pack(fill='x')
        header_frame.pack_propagate(False)

        # Icon and title
        header_content = tk.Frame(header_frame, bg=color)
        header_content.pack(expand=True, fill='both')

        icon_label = tk.Label(header_content, text=icon,
                             font=(Fonts.PRIMARY, 16),
                             fg=Colors.TEXT_WHITE, bg=color)
        icon_label.pack(side='left', padx=10, pady=8)

        title_label = tk.Label(header_content, text=title,
                              font=(Fonts.PRIMARY, Fonts.SMALL, 'bold'),
                              fg=Colors.TEXT_WHITE, bg=color)
        title_label.pack(side='left', pady=8)

        # Value display
        value_frame = tk.Frame(card_frame, bg=Colors.BG_CARD)
        value_frame.pack(fill='x', pady=15)

        value_label = tk.Label(value_frame, text=str(value),
                              font=(Fonts.PRIMARY, Fonts.TITLE, 'bold'),
                              fg=color, bg=Colors.BG_CARD)
        value_label.pack()

    def create_activity_charts(self, parent: tk.Frame) -> None:
        """
        Create activity charts section.
        """
        # Get dashboard data
        dashboard_data = self.db.get_user_dashboard_data(self.current_user_id)
        monthly_activity = dashboard_data.get('monthly_activity', [])

        # Charts container
        charts_frame = self.create_section_frame(parent, "📈 Activity Overview", Colors.INFO)

        if monthly_activity:
            # Create simple text-based chart
            chart_text = "Monthly Signing Activity (Last 12 Months):\n\n"
            max_count = max([count for _, count in monthly_activity]) if monthly_activity else 1

            for month, count in monthly_activity:
                bar_length = int((count / max_count) * 30) if max_count > 0 else 0
                bar = "█" * bar_length + "░" * (30 - bar_length)
                chart_text += f"{month}: {bar} ({count})\n"

            chart_label = tk.Label(charts_frame, text=chart_text,
                                  font=(Fonts.SECONDARY, Fonts.SMALL),
                                  fg=Colors.TEXT_PRIMARY, bg=Colors.BG_CARD,
                                  justify='left', anchor='w')
            chart_label.pack(anchor='w', padx=10, pady=10)
        else:
            no_data_label = tk.Label(charts_frame, text="No activity data available yet.\nStart signing documents to see your activity chart!",
                                    font=(Fonts.PRIMARY, Fonts.BODY),
                                    fg=Colors.TEXT_SECONDARY, bg=Colors.BG_CARD,
                                    justify='center')
            no_data_label.pack(pady=20)

    def create_recent_activity(self, parent: tk.Frame) -> None:
        """
        Create recent activity section.
        """
        # Get dashboard data
        dashboard_data = self.db.get_user_dashboard_data(self.current_user_id)
        recent_docs = dashboard_data.get('recent_documents', [])

        # Recent activity container
        activity_frame = self.create_section_frame(parent, "📋 Recent Documents", Colors.SUCCESS)

        if recent_docs:
            # Create table-like display
            for doc_name, signed_at, verification_count in recent_docs[:5]:  # Show top 5
                doc_row = tk.Frame(activity_frame, bg=Colors.BG_CARD)
                doc_row.pack(fill='x', pady=2, padx=10)

                # Document icon and name
                doc_info = tk.Frame(doc_row, bg=Colors.BG_CARD)
                doc_info.pack(side='left', fill='x', expand=True)

                tk.Label(doc_info, text="📄", font=(Fonts.PRIMARY, 12),
                        bg=Colors.BG_CARD).pack(side='left', padx=(0, 5))

                tk.Label(doc_info, text=doc_name,
                        font=(Fonts.PRIMARY, Fonts.BODY),
                        fg=Colors.TEXT_PRIMARY, bg=Colors.BG_CARD).pack(side='left')

                # Stats
                stats_info = tk.Frame(doc_row, bg=Colors.BG_CARD)
                stats_info.pack(side='right')

                tk.Label(stats_info, text=f"✅ {verification_count}",
                        font=(Fonts.PRIMARY, Fonts.SMALL),
                        fg=Colors.SUCCESS, bg=Colors.BG_CARD).pack(side='right', padx=5)

                tk.Label(stats_info, text=signed_at[:10],
                        font=(Fonts.PRIMARY, Fonts.SMALL),
                        fg=Colors.TEXT_SECONDARY, bg=Colors.BG_CARD).pack(side='right', padx=5)
        else:
            no_docs_label = tk.Label(activity_frame, text="No documents signed yet.\nSign your first document to see it here!",
                                    font=(Fonts.PRIMARY, Fonts.BODY),
                                    fg=Colors.TEXT_SECONDARY, bg=Colors.BG_CARD,
                                    justify='center')
            no_docs_label.pack(pady=20)

    def create_certificate_status(self, parent: tk.Frame) -> None:
        """
        Create certificate status monitoring.
        """
        # Get dashboard data
        dashboard_data = self.db.get_user_dashboard_data(self.current_user_id)
        cert_info = dashboard_data.get('certificate', {})

        # Certificate status container
        cert_frame = self.create_section_frame(parent, "🔐 Certificate Status", Colors.WARNING)

        if cert_info:
            # Certificate details
            details_frame = tk.Frame(cert_frame, bg=Colors.BG_CARD)
            details_frame.pack(fill='x', padx=10, pady=10)

            # Serial number
            serial_row = tk.Frame(details_frame, bg=Colors.BG_CARD)
            serial_row.pack(fill='x', pady=2)
            tk.Label(serial_row, text="Serial Number:",
                    font=(Fonts.PRIMARY, Fonts.BODY, 'bold'),
                    fg=Colors.TEXT_PRIMARY, bg=Colors.BG_CARD).pack(side='left')
            tk.Label(serial_row, text=cert_info.get('serial_number', 'N/A'),
                    font=(Fonts.SECONDARY, Fonts.SMALL),
                    fg=Colors.TEXT_SECONDARY, bg=Colors.BG_CARD).pack(side='right')

            # Subject name
            subject_row = tk.Frame(details_frame, bg=Colors.BG_CARD)
            subject_row.pack(fill='x', pady=2)
            tk.Label(subject_row, text="Subject:",
                    font=(Fonts.PRIMARY, Fonts.BODY, 'bold'),
                    fg=Colors.TEXT_PRIMARY, bg=Colors.BG_CARD).pack(side='left')
            tk.Label(subject_row, text=cert_info.get('subject_name', 'N/A'),
                    font=(Fonts.PRIMARY, Fonts.SMALL),
                    fg=Colors.TEXT_SECONDARY, bg=Colors.BG_CARD).pack(side='right')

            # Validity period
            valid_row = tk.Frame(details_frame, bg=Colors.BG_CARD)
            valid_row.pack(fill='x', pady=2)
            tk.Label(valid_row, text="Valid Until:",
                    font=(Fonts.PRIMARY, Fonts.BODY, 'bold'),
                    fg=Colors.TEXT_PRIMARY, bg=Colors.BG_CARD).pack(side='left')

            valid_until = cert_info.get('valid_until', '')
            if valid_until:
                # Check if certificate is expiring soon (within 30 days)
                try:
                    from datetime import datetime
                    if isinstance(valid_until, str):
                        valid_date = datetime.fromisoformat(valid_until.replace('Z', '+00:00'))
                    else:
                        valid_date = valid_until

                    days_until_expiry = (valid_date - datetime.now(timezone.utc)).days

                    if days_until_expiry < 30:
                        color = Colors.ERROR
                        status = f"⚠️ Expires in {days_until_expiry} days"
                    elif days_until_expiry < 90:
                        color = Colors.WARNING
                        status = f"⚠️ Expires in {days_until_expiry} days"
                    else:
                        color = Colors.SUCCESS
                        status = f"✅ Valid ({days_until_expiry} days remaining)"
                except:
                    color = Colors.TEXT_SECONDARY
                    status = str(valid_until)[:10]
            else:
                color = Colors.TEXT_SECONDARY
                status = "N/A"

            tk.Label(valid_row, text=status,
                    font=(Fonts.PRIMARY, Fonts.SMALL),
                    fg=color, bg=Colors.BG_CARD).pack(side='right')
        else:
            no_cert_label = tk.Label(cert_frame, text="No certificate information available.",
                                    font=(Fonts.PRIMARY, Fonts.BODY),
                                    fg=Colors.TEXT_SECONDARY, bg=Colors.BG_CARD)
            no_cert_label.pack(pady=20)

    def create_documents_tab(self) -> None:
        """
        Create enhanced documents management tab.
        """
        # Use the scrollable content area
        docs_scrollable = self.scrollable_content

        # Smart document management sections
        self.create_quick_actions(docs_scrollable)
        self.create_recent_documents_section(docs_scrollable)
        self.create_favorites_section(docs_scrollable)
        self.create_categories_section(docs_scrollable)

    def create_quick_actions(self, parent: tk.Frame) -> None:
        """
        Create quick actions section.
        """
        actions_frame = self.create_section_frame(parent, "⚡ Quick Actions", Colors.INFO)

        # Search bar
        search_container = tk.Frame(actions_frame, bg=Colors.BG_CARD)
        search_container.pack(fill='x', pady=(0, 15))

        tk.Label(search_container, text="🔍 Search Documents:",
                font=(Fonts.PRIMARY, Fonts.BODY, 'bold'),
                fg=Colors.TEXT_PRIMARY, bg=Colors.BG_CARD).pack(anchor='w')

        search_frame = tk.Frame(search_container, bg=Colors.BG_CARD)
        search_frame.pack(fill='x', pady=(5, 0))

        self.search_entry = tk.Entry(search_frame,
                                    font=(Fonts.PRIMARY, Fonts.BODY),
                                    bg=Colors.BG_MAIN, fg=Colors.TEXT_PRIMARY,
                                    relief='flat', bd=1)
        self.search_entry.pack(side='left', fill='x', expand=True, padx=(0, 10), ipady=5)
        self.search_entry.bind('<KeyRelease>', self.on_search_change)

        search_btn = self.create_modern_button(search_frame, "Search",
                                              self.perform_document_search, Colors.INFO)
        search_btn.pack(side='right')

        # Quick action buttons
        buttons_frame = tk.Frame(actions_frame, bg=Colors.BG_CARD)
        buttons_frame.pack(fill='x', pady=(10, 0))

        refresh_btn = self.create_modern_button(buttons_frame, "🔄 Refresh",
                                               self.refresh_documents, Colors.BUTTON_PRIMARY)
        refresh_btn.pack(side='left', padx=(0, 10))

        favorites_btn = self.create_modern_button(buttons_frame, "⭐ Show Favorites",
                                                 self.show_favorites, Colors.WARNING)
        favorites_btn.pack(side='left', padx=(0, 10))

        categories_btn = self.create_modern_button(buttons_frame, "📁 Categories",
                                                  self.show_categories, Colors.SUCCESS)
        categories_btn.pack(side='left')

    def create_recent_documents_section(self, parent: tk.Frame) -> None:
        """
        Create recent documents section.
        """
        recent_frame = self.create_section_frame(parent, "📄 Recent Documents", Colors.SUCCESS)

        # Get recent documents
        recent_docs = self.db.get_recent_documents(self.current_user_id, 5)

        if recent_docs:
            for doc_id, doc_name, doc_path, signed_at, verification_count, category, is_favorite in recent_docs:
                self.create_document_item(recent_frame, doc_id, doc_name, doc_path,
                                        signed_at, verification_count, category, is_favorite)
        else:
            no_docs_label = tk.Label(recent_frame, text="No recent documents found.\nSign your first document to see it here!",
                                    font=(Fonts.PRIMARY, Fonts.BODY),
                                    fg=Colors.TEXT_SECONDARY, bg=Colors.BG_CARD,
                                    justify='center')
            no_docs_label.pack(pady=20)

    def create_favorites_section(self, parent: tk.Frame) -> None:
        """
        Create favorites section.
        """
        favorites_frame = self.create_section_frame(parent, "⭐ Favorite Documents", Colors.WARNING)

        # Get favorite documents
        favorite_docs = self.db.get_favorite_documents(self.current_user_id)

        if favorite_docs:
            for doc_id, doc_name, doc_path, signed_at, verification_count, category in favorite_docs:
                self.create_document_item(favorites_frame, doc_id, doc_name, doc_path,
                                        signed_at, verification_count, category, True)
        else:
            no_favorites_label = tk.Label(favorites_frame, text="No favorite documents yet.\nClick the ⭐ button on any document to add it to favorites!",
                                         font=(Fonts.PRIMARY, Fonts.BODY),
                                         fg=Colors.TEXT_SECONDARY, bg=Colors.BG_CARD,
                                         justify='center')
            no_favorites_label.pack(pady=20)

    def create_categories_section(self, parent: tk.Frame) -> None:
        """
        Create categories section.
        """
        categories_frame = self.create_section_frame(parent, "📁 Document Categories", Colors.LIGHT_BLUE)

        # Get categories
        categories = self.db.get_document_categories(self.current_user_id)

        if categories:
            for category, count in categories:
                cat_row = tk.Frame(categories_frame, bg=Colors.BG_CARD)
                cat_row.pack(fill='x', pady=2, padx=10)

                # Category info
                cat_info = tk.Frame(cat_row, bg=Colors.BG_CARD)
                cat_info.pack(side='left', fill='x', expand=True)

                tk.Label(cat_info, text="📁", font=(Fonts.PRIMARY, 12),
                        bg=Colors.BG_CARD).pack(side='left', padx=(0, 5))

                tk.Label(cat_info, text=f"{category} ({count})",
                        font=(Fonts.PRIMARY, Fonts.BODY),
                        fg=Colors.TEXT_PRIMARY, bg=Colors.BG_CARD).pack(side='left')

                # View button
                view_btn = self.create_modern_button(cat_row, "View",
                                                    lambda c=category: self.show_category_documents(c),
                                                    Colors.LIGHT_BLUE)
                view_btn.pack(side='right')
        else:
            no_categories_label = tk.Label(categories_frame, text="No categories yet.\nDocuments will be automatically categorized as you sign them!",
                                          font=(Fonts.PRIMARY, Fonts.BODY),
                                          fg=Colors.TEXT_SECONDARY, bg=Colors.BG_CARD,
                                          justify='center')
            no_categories_label.pack(pady=20)

    def create_document_item(self, parent: tk.Frame, doc_id: int, doc_name: str, doc_path: str, signed_at: str, verification_count: int, category: str, is_favorite: bool) -> None:
        """
        Create a document item display.
        """
        item_frame = tk.Frame(parent, bg=Colors.BG_MAIN, relief='flat', bd=1)
        item_frame.pack(fill='x', pady=2, padx=10)

        # Document info
        info_frame = tk.Frame(item_frame, bg=Colors.BG_MAIN)
        info_frame.pack(side='left', fill='x', expand=True, padx=10, pady=5)

        # Name and category
        name_frame = tk.Frame(info_frame, bg=Colors.BG_MAIN)
        name_frame.pack(fill='x')

        tk.Label(name_frame, text="📄", font=(Fonts.PRIMARY, 12),
                bg=Colors.BG_MAIN).pack(side='left', padx=(0, 5))

        tk.Label(name_frame, text=doc_name,
                font=(Fonts.PRIMARY, Fonts.BODY, 'bold'),
                fg=Colors.TEXT_PRIMARY, bg=Colors.BG_MAIN).pack(side='left')

        tk.Label(name_frame, text=f"[{category}]",
                font=(Fonts.PRIMARY, Fonts.SMALL),
                fg=Colors.TEXT_SECONDARY, bg=Colors.BG_MAIN).pack(side='right')

        # Stats
        stats_frame = tk.Frame(info_frame, bg=Colors.BG_MAIN)
        stats_frame.pack(fill='x', pady=(2, 0))

        tk.Label(stats_frame, text=f"Signed: {signed_at[:10]}",
                font=(Fonts.PRIMARY, Fonts.SMALL),
                fg=Colors.TEXT_SECONDARY, bg=Colors.BG_MAIN).pack(side='left')

        tk.Label(stats_frame, text=f"✅ {verification_count} verifications",
                font=(Fonts.PRIMARY, Fonts.SMALL),
                fg=Colors.SUCCESS, bg=Colors.BG_MAIN).pack(side='right')

        # Action buttons
        actions_frame = tk.Frame(item_frame, bg=Colors.BG_MAIN)
        actions_frame.pack(side='right', padx=10, pady=5)

        # Favorite button
        fav_color = Colors.WARNING if is_favorite else Colors.TEXT_SECONDARY
        fav_btn = tk.Button(actions_frame, text="⭐",
                           command=lambda: self.toggle_favorite(doc_id),
                           bg=Colors.BG_MAIN, fg=fav_color,
                           font=(Fonts.PRIMARY, 12), relief='flat', bd=0,
                           cursor='hand2')
        fav_btn.pack(side='left', padx=2)

        # Re-sign button
        resign_btn = self.create_modern_button(actions_frame, "Re-sign",
                                              lambda: self.resign_document(doc_path),
                                              Colors.SUCCESS)
        resign_btn.pack(side='left', padx=2)

    def on_search_change(self, event: tk.Event) -> None:
        """
        Handle search input changes.
        """
        # Implement real-time search if needed
        pass

    def perform_document_search(self) -> None:
        """
        Perform document search.
        """
        search_term = self.search_entry.get().strip()
        if search_term:
            results = self.db.search_documents(self.current_user_id, search_term)
            self.show_search_results(results, search_term)
        else:
            messagebox.showinfo("Search", "Please enter a search term.")

    def show_search_results(self, results: List[Tuple[Any, ...]], search_term: str) -> None:
        """
        Show search results in a new window.
        """
        if not results:
            messagebox.showinfo("Search Results", f"No documents found for '{search_term}'.")
            return

        # Create search results window
        results_window = tk.Toplevel(self.root)
        results_window.title(f"Search Results: '{search_term}'")
        results_window.geometry("800x600")
        results_window.configure(bg=Colors.BG_MAIN)

        # Results header
        header_label = tk.Label(results_window,
                               text=f"Found {len(results)} documents for '{search_term}'",
                               font=(Fonts.PRIMARY, Fonts.HEADING, 'bold'),
                               fg=Colors.TEXT_PRIMARY, bg=Colors.BG_MAIN)
        header_label.pack(pady=20)

        # Results list
        results_frame = tk.Frame(results_window, bg=Colors.BG_MAIN)
        results_frame.pack(fill='both', expand=True, padx=20, pady=(0, 20))

        for doc_id, doc_name, doc_path, signed_at, verification_count, category, is_favorite in results:
            self.create_document_item(results_frame, doc_id, doc_name, doc_path,
                                    signed_at, verification_count, category, is_favorite)

    def refresh_documents(self) -> None:
        """
        Refresh document lists.
        """
        # Recreate the documents tab
        for widget in self.documents_frame.winfo_children():
            widget.destroy()
        self.create_documents_tab()
        messagebox.showinfo("Refresh", "Document lists refreshed successfully!")

    def show_favorites(self) -> None:
        """
        Show only favorite documents.
        """
        favorites = self.db.get_favorite_documents(self.current_user_id)
        if favorites:
            self.show_document_list(favorites, "⭐ Favorite Documents")
        else:
            messagebox.showinfo("Favorites", "No favorite documents found.")

    def show_categories(self) -> None:
        """
        Show category management dialog.
        """
        categories = self.db.get_document_categories(self.current_user_id)
        if categories:
            category_text = "Document Categories:\n\n"
            for category, count in categories:
                category_text += f"📁 {category}: {count} documents\n"
            messagebox.showinfo("Categories", category_text)
        else:
            messagebox.showinfo("Categories", "No categories found.")

    def show_category_documents(self, category: str) -> None:
        """
        Show documents in a specific category.
        """
        docs = self.db.get_documents_by_category(self.current_user_id, category)
        if docs:
            self.show_document_list(docs, f"📁 Category: {category}")
        else:
            messagebox.showinfo("Category", f"No documents found in category '{category}'.")

    def show_document_list(self, documents: List[Tuple[Any, ...]], title: str) -> None:
        """
        Show a list of documents in a new window.
        """
        # Create document list window
        list_window = tk.Toplevel(self.root)
        list_window.title(title)
        list_window.geometry("900x700")
        list_window.configure(bg=Colors.BG_MAIN)

        # Header
        header_label = tk.Label(list_window, text=title,
                               font=(Fonts.PRIMARY, Fonts.HEADING, 'bold'),
                               fg=Colors.TEXT_PRIMARY, bg=Colors.BG_MAIN)
        header_label.pack(pady=20)

        # Document list
        list_frame = tk.Frame(list_window, bg=Colors.BG_MAIN)
        list_frame.pack(fill='both', expand=True, padx=20, pady=(0, 20))

        for doc_data in documents:
            if len(doc_data) == 6:  # Favorites format
                doc_id, doc_name, doc_path, signed_at, verification_count, category = doc_data
                is_favorite = True
            else:  # Regular format
                doc_id, doc_name, doc_path, signed_at, verification_count, category, is_favorite = doc_data

            self.create_document_item(list_frame, doc_id, doc_name, doc_path,
                                    signed_at, verification_count, category, is_favorite)

    def toggle_favorite(self, document_id: int) -> None:
        """
        Toggle favorite status of a document.
        """
        self.db.toggle_document_favorite(document_id)
        self.refresh_documents()
        messagebox.showinfo("Favorite", "Document favorite status updated!")

    def resign_document(self, document_path: str) -> None:
        """
        Re-sign an existing document.
        """
        if os.path.exists(document_path):
            self.document_path = document_path
            filename = os.path.basename(document_path)
            self.doc_path_label.config(text=f"📄 {filename}",
                                      fg=Colors.SUCCESS, bg=Colors.BG_MAIN)
            self.animate_selection_feedback(self.doc_path_label)

            # Switch to signing tab
            self.user_notebook.select(1)  # Documents tab
            messagebox.showinfo("Re-sign", f"Document '{filename}' loaded for re-signing.\nClick 'Sign Document' to create a new signature.")
        else:
            messagebox.showerror("Error", f"Document file not found: {document_path}")

    def create_settings_tab(self) -> None:
        """
        Create settings and logout tab.
        """
        self.create_logout_section(self.settings_frame)

    def create_logout_section(self, parent: tk.Frame) -> None:
        """
        Create modern logout section.
        """
        logout_frame = self.create_section_frame(parent, "🚪 Session Management", Colors.ERROR)

        # Description with modern typography
        desc_label = tk.Label(logout_frame,
                             text="End your current session and return to the main authentication interface",
                             font=(Fonts.PRIMARY, Fonts.BODY),
                             fg=Colors.TEXT_SECONDARY, bg=Colors.BG_CARD,
                             wraplength=600, justify='center')
        desc_label.pack(pady=(0, 25))

        # Modern logout button
        button_container = tk.Frame(logout_frame, bg=Colors.BG_CARD)
        button_container.pack(pady=15)

        logout_button = self.create_modern_button(button_container, "🔓 Logout from System",
                                                 self.perform_logout, Colors.BUTTON_DANGER)
        logout_button.pack()
    
    def create_section_frame(self, parent: tk.Frame, title: str, color: str) -> tk.Frame:
        """
        Create a modern responsive card-based section frame.
        """
        # Get responsive padding
        window_width = self.root.winfo_width() if self.root.winfo_width() > 1 else 1400

        if window_width < 1000:
            container_padx = 10
            content_padx = 15
            content_pady = 15
        elif window_width < 1300:
            container_padx = 15
            content_padx = 20
            content_pady = 18
        else:
            container_padx = 20
            content_padx = 25
            content_pady = 20

        # Container for shadow effect - responsive padding
        container = tk.Frame(parent, bg=Colors.BG_MAIN)
        container.pack(fill='both', expand=True, pady=15, padx=container_padx)

        # Shadow frame
        shadow_frame = tk.Frame(container, bg=Colors.BORDER_LIGHT, height=2)
        shadow_frame.pack(fill='x', pady=(2, 0))

        # Main card frame - ensure it fills width
        section_frame = tk.Frame(container, bg=Colors.BG_CARD, relief='flat', bd=0)
        section_frame.pack(fill='both', expand=True)

        # Header section with colored accent - responsive height
        header_height = 45 if window_width < 1000 else 50
        header_frame = tk.Frame(section_frame, bg=color, height=header_height)
        header_frame.pack(fill='x')
        header_frame.pack_propagate(False)

        # Title with responsive typography
        font_size = Fonts.SUBHEADING if window_width < 1000 else Fonts.HEADING
        title_label = tk.Label(header_frame, text=title,
                              font=(Fonts.PRIMARY, font_size, 'bold'),
                              fg=Colors.TEXT_WHITE, bg=color)
        title_label.pack(expand=True, pady=10)

        # Content area - responsive padding
        content_frame = tk.Frame(section_frame, bg=Colors.BG_CARD)
        content_frame.pack(fill='both', expand=True, padx=content_padx, pady=content_pady)

        return content_frame

    def create_modern_button(self, parent: tk.Frame, text: str, command: Callable, bg_color: str, hover_color: Optional[str] = None) -> tk.Button:
        """
        Create a modern responsive button with hover effects.
        """
        if hover_color is None:
            hover_color = Colors.BUTTON_HOVER

        # Responsive button sizing
        window_width = self.root.winfo_width() if self.root.winfo_width() > 1 else 1400

        if window_width < 1000:
            padx, pady = 20, 10
            font_size = Fonts.SMALL
        elif window_width < 1300:
            padx, pady = 22, 11
            font_size = Fonts.BODY
        else:
            padx, pady = 25, 12
            font_size = Fonts.BODY

        button = tk.Button(parent, text=text, command=command,
                          bg=bg_color, fg=Colors.TEXT_WHITE,
                          font=(Fonts.PRIMARY, font_size, 'bold'),
                          relief='flat', bd=0, padx=padx, pady=pady,
                          cursor='hand2', activebackground=hover_color,
                          activeforeground=Colors.TEXT_WHITE)

        # Add hover effects
        def on_enter(e: tk.Event):
            button.config(bg=hover_color)

        def on_leave(e: tk.Event):
            button.config(bg=bg_color)

        button.bind("<Enter>", on_enter)
        button.bind("<Leave>", on_leave)

        return button

    def animate_button_click(self, button: tk.Button, original_color: str, click_color: str) -> None:
        """
        Animate button click with color change.
        """
        button.config(bg=click_color)
        self.root.after(100, lambda: button.config(bg=original_color))

    def create_registration_section(self, parent: tk.Frame) -> None:
        """
        Create modern user registration section with password.
        """
        reg_frame = self.create_section_frame(parent, "👤 User Registration", Colors.INFO)
        window_width = self.root.winfo_width() if self.root.winfo_width() > 1 else 1400
        wrap_length = min(600, window_width - 100)
        desc_text = "Create a new user account with RSA-2048 key pair, X.509 certificate, and password"
        if window_width < 1000:
            desc_text = "Create new user with RSA key pair, certificate, and password"
        desc_label = tk.Label(reg_frame, text=desc_text,
                             font=(Fonts.PRIMARY, Fonts.BODY),
                             fg=Colors.TEXT_SECONDARY, bg=Colors.BG_CARD,
                             wraplength=wrap_length, justify='center')
        desc_label.pack(pady=(0, 20))
        input_container = tk.Frame(reg_frame, bg=Colors.BG_CARD)
        input_container.pack(pady=10)
        input_frame = tk.Frame(input_container, bg=Colors.BG_CARD)
        input_frame.pack()
        username_label = tk.Label(input_frame, text="Username:",
                                 font=(Fonts.PRIMARY, Fonts.BODY, 'bold'),
                                 fg=Colors.TEXT_PRIMARY, bg=Colors.BG_CARD)
        username_label.pack(side='left', padx=(0, 10))
        self.username_entry = tk.Entry(input_frame,
                                      font=(Fonts.PRIMARY, Fonts.BODY),
                                      width=15, relief='flat', bd=1,
                                      bg=Colors.BG_MAIN, fg=Colors.TEXT_PRIMARY,
                                      insertbackground=Colors.TEXT_PRIMARY)
        self.username_entry.pack(side='left', padx=10, ipady=8)
        # Password fields
        password_label = tk.Label(input_frame, text="Password:", font=(Fonts.PRIMARY, Fonts.BODY, 'bold'), fg=Colors.TEXT_PRIMARY, bg=Colors.BG_CARD)
        password_label.pack(side='left', padx=(20, 10))
        self.password_entry = tk.Entry(input_frame, show='*', font=(Fonts.PRIMARY, Fonts.BODY), width=15, relief='flat', bd=1, bg=Colors.BG_MAIN, fg=Colors.TEXT_PRIMARY, insertbackground=Colors.TEXT_PRIMARY)
        self.password_entry.pack(side='left', padx=10, ipady=8)
        confirm_label = tk.Label(input_frame, text="Confirm:", font=(Fonts.PRIMARY, Fonts.BODY, 'bold'), fg=Colors.TEXT_PRIMARY, bg=Colors.BG_CARD)
        confirm_label.pack(side='left', padx=(20, 10))
        self.confirm_entry = tk.Entry(input_frame, show='*', font=(Fonts.PRIMARY, Fonts.BODY), width=15, relief='flat', bd=1, bg=Colors.BG_MAIN, fg=Colors.TEXT_PRIMARY, insertbackground=Colors.TEXT_PRIMARY)
        self.confirm_entry.pack(side='left', padx=10, ipady=8)
        self.register_button = self.create_modern_button(
            input_frame, "Register User", self.register_user, Colors.BUTTON_PRIMARY)
        self.register_button.pack(side='left', padx=15)
        self.reg_status_label = tk.Label(reg_frame, text="",
                                        font=(Fonts.PRIMARY, Fonts.BODY),
                                        bg=Colors.BG_CARD, wraplength=600)
        self.reg_status_label.pack(pady=(15, 0))

    def create_login_section(self, parent: tk.Frame) -> None:
        """
        Create modern username-based login section with password.
        """
        login_frame = self.create_section_frame(parent, "🔑 User Authentication", Colors.WARNING)
        desc_label = tk.Label(login_frame,
                             text="Enter your username and password to authenticate",
                             font=(Fonts.PRIMARY, Fonts.BODY),
                             fg=Colors.TEXT_SECONDARY, bg=Colors.BG_CARD,
                             wraplength=600, justify='center')
        desc_label.pack(pady=(0, 25))
        input_container = tk.Frame(login_frame, bg=Colors.BG_CARD)
        input_container.pack(pady=10)
        input_frame = tk.Frame(input_container, bg=Colors.BG_CARD)
        input_frame.pack()
        username_label = tk.Label(input_frame, text="Username:",
                                 font=(Fonts.PRIMARY, Fonts.BODY, 'bold'),
                                 fg=Colors.TEXT_PRIMARY, bg=Colors.BG_CARD)
        username_label.pack(side='left', padx=(0, 10))
        self.login_username_entry = tk.Entry(input_frame,
                                           font=(Fonts.PRIMARY, Fonts.BODY),
                                           width=15, relief='flat', bd=1,
                                           bg=Colors.BG_MAIN, fg=Colors.TEXT_PRIMARY,
                                           insertbackground=Colors.TEXT_PRIMARY)
        self.login_username_entry.pack(side='left', padx=10, ipady=8)
        password_label = tk.Label(input_frame, text="Password:", font=(Fonts.PRIMARY, Fonts.BODY, 'bold'), fg=Colors.TEXT_PRIMARY, bg=Colors.BG_CARD)
        password_label.pack(side='left', padx=(20, 10))
        self.login_password_entry = tk.Entry(input_frame, show='*', font=(Fonts.PRIMARY, Fonts.BODY), width=15, relief='flat', bd=1, bg=Colors.BG_MAIN, fg=Colors.TEXT_PRIMARY, insertbackground=Colors.TEXT_PRIMARY)
        self.login_password_entry.pack(side='left', padx=10, ipady=8)
        self.login_username_entry.bind('<Return>', lambda e: self.perform_login())
        self.login_password_entry.bind('<Return>', lambda e: self.perform_login())
        self.login_button = self.create_modern_button(input_frame, "🔓 Login",
                                                     self.perform_login, Colors.BUTTON_SUCCESS)
        self.login_button.pack(side='left', padx=15)
        status_container = tk.Frame(login_frame, bg=Colors.BG_CARD)
        status_container.pack(fill='x', pady=(20, 0))
        self.key_status_label = tk.Label(status_container, text="🔑 Private key: Not loaded",
                                        font=(Fonts.PRIMARY, Fonts.SMALL),
                                        fg=Colors.TEXT_SECONDARY, bg=Colors.BG_CARD)
        self.key_status_label.pack(anchor='w', pady=2)
        self.cert_status_label = tk.Label(status_container, text="📜 Certificate: Not loaded",
                                         font=(Fonts.PRIMARY, Fonts.SMALL),
                                         fg=Colors.TEXT_SECONDARY, bg=Colors.BG_CARD)
        self.cert_status_label.pack(anchor='w', pady=2)
        manual_frame = tk.Frame(login_frame, bg=Colors.BG_CARD)
        manual_frame.pack(fill='x', pady=(15, 0))
        manual_label = tk.Label(manual_frame, text="Advanced: Manual file selection",
                               font=(Fonts.PRIMARY, Fonts.SMALL, 'italic'),
                               fg=Colors.TEXT_SECONDARY, bg=Colors.BG_CARD)
        manual_label.pack(anchor='w')
        manual_buttons = tk.Frame(manual_frame, bg=Colors.BG_CARD)
        manual_buttons.pack(anchor='w', pady=(5, 0))
        key_browse_btn = self.create_modern_button(manual_buttons, "Browse Key",
                                                  self.select_private_key, Colors.BUTTON_PRIMARY)
        key_browse_btn.pack(side='left', padx=(0, 10))
        cert_browse_btn = self.create_modern_button(manual_buttons, "Browse Cert",
                                                   self.select_certificate, Colors.WARNING)
        cert_browse_btn.pack(side='left')
        self.login_status_label = tk.Label(login_frame, text="",
                                          font=(Fonts.PRIMARY, Fonts.BODY),
                                          bg=Colors.BG_CARD, wraplength=600)
        self.login_status_label.pack(pady=(15, 0))

    def create_signing_section(self, parent: tk.Frame) -> None:
        """
        Create modern document signing section (only shown after login).
        """
        sign_frame = self.create_section_frame(parent, "✍️ Document Signing", Colors.SUCCESS)

        # Description with modern typography
        desc_label = tk.Label(sign_frame,
                             text="Sign documents with your digital signature using RSA-PSS cryptography",
                             font=(Fonts.PRIMARY, Fonts.BODY),
                             fg=Colors.TEXT_SECONDARY, bg=Colors.BG_CARD,
                             wraplength=600, justify='center')
        desc_label.pack(pady=(0, 25))

        # Modern document selection container
        doc_container = tk.Frame(sign_frame, bg=Colors.BG_CARD)
        doc_container.pack(fill='x', pady=10)

        # Document selection with modern styling
        doc_section = tk.Frame(doc_container, bg=Colors.BG_CARD)
        doc_section.pack(fill='x', pady=8)

        doc_label = tk.Label(doc_section, text="Document to Sign:",
                            font=(Fonts.PRIMARY, Fonts.BODY, 'bold'),
                            fg=Colors.TEXT_PRIMARY, bg=Colors.BG_CARD)
        doc_label.pack(anchor='w')

        doc_row = tk.Frame(doc_section, bg=Colors.BG_CARD)
        doc_row.pack(fill='x', pady=(5, 0))

        self.doc_path_label = tk.Label(doc_row, text="📄 No document selected",
                                      font=(Fonts.PRIMARY, Fonts.SMALL),
                                      fg=Colors.ERROR, bg=Colors.BG_MAIN,
                                      relief='flat', bd=1, padx=10, pady=8,
                                      anchor='w')
        self.doc_path_label.pack(side='left', fill='x', expand=True, padx=(0, 10))

        doc_browse_btn = self.create_modern_button(doc_row, "Browse Documents",
                                                  self.select_document, Colors.SUCCESS)
        doc_browse_btn.pack(side='right')

        # Modern sign button
        button_container = tk.Frame(sign_frame, bg=Colors.BG_CARD)
        button_container.pack(pady=25)

        self.sign_button = self.create_modern_button(button_container, "🖊️ Sign Document",
                                                    self.sign_document, Colors.BUTTON_SUCCESS)
        self.sign_button.pack()

        # Status label with modern styling
        self.sign_status_label = tk.Label(sign_frame, text="Ready to sign documents",
                                         font=(Fonts.PRIMARY, Fonts.BODY),
                                         fg=Colors.SUCCESS, bg=Colors.BG_CARD, wraplength=600)
        self.sign_status_label.pack(pady=(15, 0))

    def create_verification_section(self, parent: tk.Frame) -> None:
        """
        Create modern document verification section.
        """
        verify_frame = self.create_section_frame(parent, "✅ Document Verification", Colors.LIGHT_BLUE)

        # Description with modern typography
        desc_label = tk.Label(verify_frame,
                             text="Verify the authenticity and integrity of digitally signed documents",
                             font=(Fonts.PRIMARY, Fonts.BODY),
                             fg=Colors.TEXT_SECONDARY, bg=Colors.BG_CARD,
                             wraplength=600, justify='center')
        desc_label.pack(pady=(0, 25))

        # Modern file selection container
        file_container = tk.Frame(verify_frame, bg=Colors.BG_CARD)
        file_container.pack(fill='x', pady=10)

        # Original document selection with modern styling
        orig_section = tk.Frame(file_container, bg=Colors.BG_CARD)
        orig_section.pack(fill='x', pady=8)

        orig_label = tk.Label(orig_section, text="Original Document:",
                             font=(Fonts.PRIMARY, Fonts.BODY, 'bold'),
                             fg=Colors.TEXT_PRIMARY, bg=Colors.BG_CARD)
        orig_label.pack(anchor='w')

        orig_row = tk.Frame(orig_section, bg=Colors.BG_CARD)
        orig_row.pack(fill='x', pady=(5, 0))

        self.orig_doc_label = tk.Label(orig_row, text="📄 No document selected",
                                      font=(Fonts.PRIMARY, Fonts.SMALL),
                                      fg=Colors.ERROR, bg=Colors.BG_MAIN,
                                      relief='flat', bd=1, padx=10, pady=8,
                                      anchor='w')
        self.orig_doc_label.pack(side='left', fill='x', expand=True, padx=(0, 10))

        orig_browse_btn = self.create_modern_button(orig_row, "Browse Documents",
                                                   self.select_original_document, Colors.LIGHT_BLUE)
        orig_browse_btn.pack(side='right')

        # Signature file selection with modern styling
        sig_section = tk.Frame(file_container, bg=Colors.BG_CARD)
        sig_section.pack(fill='x', pady=8)

        sig_label = tk.Label(sig_section, text="Signature File (.sig):",
                            font=(Fonts.PRIMARY, Fonts.BODY, 'bold'),
                            fg=Colors.TEXT_PRIMARY, bg=Colors.BG_CARD)
        sig_label.pack(anchor='w')

        sig_row = tk.Frame(sig_section, bg=Colors.BG_CARD)
        sig_row.pack(fill='x', pady=(5, 0))

        self.sig_file_label = tk.Label(sig_row, text="🔏 No signature selected",
                                      font=(Fonts.PRIMARY, Fonts.SMALL),
                                      fg=Colors.ERROR, bg=Colors.BG_MAIN,
                                      relief='flat', bd=1, padx=10, pady=8,
                                      anchor='w')
        self.sig_file_label.pack(side='left', fill='x', expand=True, padx=(0, 10))

        sig_browse_btn = self.create_modern_button(sig_row, "Browse Signatures",
                                                  self.select_signature_file, Colors.LIGHT_BLUE)
        sig_browse_btn.pack(side='right')

        # Certificate file selection with modern styling
        cert_section = tk.Frame(file_container, bg=Colors.BG_CARD)
        cert_section.pack(fill='x', pady=8)

        cert_label = tk.Label(cert_section, text="Certificate File (.pem):",
                             font=(Fonts.PRIMARY, Fonts.BODY, 'bold'),
                             fg=Colors.TEXT_PRIMARY, bg=Colors.BG_CARD)
        cert_label.pack(anchor='w')

        cert_row = tk.Frame(cert_section, bg=Colors.BG_CARD)
        cert_row.pack(fill='x', pady=(5, 0))

        self.cert_verify_label = tk.Label(cert_row, text="📜 No certificate selected",
                                         font=(Fonts.PRIMARY, Fonts.SMALL),
                                         fg=Colors.ERROR, bg=Colors.BG_MAIN,
                                         relief='flat', bd=1, padx=10, pady=8,
                                         anchor='w')
        self.cert_verify_label.pack(side='left', fill='x', expand=True, padx=(0, 10))

        cert_browse_btn = self.create_modern_button(cert_row, "Browse Certificates",
                                                   self.select_certificate_for_verification, Colors.LIGHT_BLUE)
        cert_browse_btn.pack(side='right')

        # Modern verify button
        button_container = tk.Frame(verify_frame, bg=Colors.BG_CARD)
        button_container.pack(pady=25)

        self.verify_button = self.create_modern_button(button_container, "🔍 Verify Document",
                                                      self.verify_document, Colors.LIGHT_BLUE)
        self.verify_button.pack()

        # Status label with modern styling
        self.verify_status_label = tk.Label(verify_frame, text="",
                                           font=(Fonts.PRIMARY, Fonts.BODY),
                                           bg=Colors.BG_CARD, wraplength=600)
        self.verify_status_label.pack(pady=(15, 0))

    def create_status_bar(self) -> None:
        """
        Create modern status bar.
        """
        # Status container
        status_container = tk.Frame(self.scrollable_frame, bg=Colors.BG_MAIN)
        status_container.pack(fill='x', side='bottom', padx=0, pady=(10, 20))

        # Modern status bar with gradient effect
        status_frame = tk.Frame(status_container, bg=Colors.BG_SIDEBAR, height=40)
        status_frame.pack(fill='x', padx=20)
        status_frame.pack_propagate(False)

        # Left side - Status indicator
        left_status = tk.Frame(status_frame, bg=Colors.BG_SIDEBAR)
        left_status.pack(side='left', fill='y', padx=20, pady=8)

        self.status_label = tk.Label(left_status, text="🟢 System Ready",
                                    font=(Fonts.PRIMARY, Fonts.BODY),
                                    fg=Colors.TEXT_WHITE, bg=Colors.BG_SIDEBAR)
        self.status_label.pack(anchor='w')

        # Right side - System information
        right_status = tk.Frame(status_frame, bg=Colors.BG_SIDEBAR)
        right_status.pack(side='right', fill='y', padx=20, pady=8)

        self.system_info_label = tk.Label(right_status, text="",
                                         font=(Fonts.PRIMARY, Fonts.SMALL),
                                         fg=Colors.TEXT_LIGHT, bg=Colors.BG_SIDEBAR)
        self.system_info_label.pack(anchor='e')

    # ==================== CORE FUNCTIONALITY METHODS ====================

    def register_user(self) -> None:
        """
        Register a new user with RSA key pair, CA-signed certificate, and password (private key encrypted).
        """
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        confirm = self.confirm_entry.get().strip()
        if not username:
            messagebox.showerror("Error", "Please enter a username!")
            return
        if not username.isalnum():
            messagebox.showerror("Error", "Username must contain only letters and numbers!")
            return
        if not password or not confirm:
            messagebox.showerror("Error", "Please enter and confirm your password!")
            return
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match!")
            return
        valid, msg = self._validate_password_strength(password)
        if not valid:
            messagebox.showerror("Error", msg)
            return
        existing_user = self.db.get_user_by_username(username)
        if existing_user:
            messagebox.showerror("Error", f"User '{username}' already exists!")
            return
        try:
            self.reg_status_label.config(text="Generating RSA key pair...", fg='#f39c12')
            self.root.update()
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            public_key = private_key.public_key()
            self.reg_status_label.config(text="Creating certificate signing request...", fg='#f39c12')
            self.root.update()
            subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Signetrix"),
                x509.NameAttribute(NameOID.COMMON_NAME, username),
            ])
            # CA signs the user's certificate
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                self.ca_cert.subject
            ).public_key(
                public_key
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.now(timezone.utc)
            ).not_valid_after(
                datetime.now(timezone.utc) + timedelta(days=365)
            ).add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            ).sign(self.ca_private_key, hashes.SHA256())
            private_key_path = f"keys/{username}_private.pem"
            public_key_path = f"keys/{username}_public.pem"
            certificate_path = f"certs/{username}_cert.pem"
            # Encrypt private key with password
            with open(private_key_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=BestAvailableEncryption(password.encode())
                ))
            with open(public_key_path, "wb") as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            with open(certificate_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            # Password hashing (PBKDF2-HMAC-SHA256)
            salt = secrets.token_hex(16)
            password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100_000).hex()
            user_id = self.db.add_user(username, private_key_path, public_key_path, certificate_path, password_hash, salt)
            self.db.add_certificate(
                user_id=user_id,
                serial_number=str(cert.serial_number),
                subject_name=str(subject),
                issuer_name=str(self.ca_cert.subject),
                valid_from=cert.not_valid_before_utc.isoformat(),
                valid_until=cert.not_valid_after_utc.isoformat(),
                certificate_path=certificate_path
            )
            # Optionally, copy CA cert to user's certs for reference
            shutil.copy2(self.ca_cert_path, f"certs/Signetrix_CA_cert.pem")
            self.db.log_audit_event(user_id, "USER_REGISTERED", f"User {username} registered successfully (CA-signed)")
            self.reg_status_label.config(text=f"✓ User '{username}' registered successfully!", fg='#27ae60')
            self.username_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)
            self.confirm_entry.delete(0, tk.END)
            self.update_system_status()
            messagebox.showinfo("Success",
                              f"User '{username}' registered successfully!\n\n"
                              f"Files created:\n"
                              f"• {private_key_path}\n"
                              f"• {public_key_path}\n"
                              f"• {certificate_path}\n"
                              f"• certs/Signetrix_CA_cert.pem (CA certificate)")
        except Exception as e:
            self.reg_status_label.config(text=f"Registration failed: {str(e)}", fg='#e74c3c')
            messagebox.showerror("Error", f"Registration failed: {str(e)}")

    def select_private_key(self) -> None:
        """
        Select private key file with modern feedback.
        """
        file_path = filedialog.askopenfilename(
            title="Select Private Key File",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")],
            initialdir="keys" if os.path.exists("keys") else "."
        )
        if file_path:
            self.private_key_path = file_path
            filename = os.path.basename(file_path)
            # Modern success feedback
            self.key_status_label.config(text=f"🔑 {filename}",
                                        fg=Colors.SUCCESS, bg=Colors.BG_CARD)
            self.animate_selection_feedback(self.key_status_label)

    def select_certificate(self) -> None:
        """
        Select certificate file with modern feedback.
        """
        file_path = filedialog.askopenfilename(
            title="Select Certificate File",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")],
            initialdir="certs" if os.path.exists("certs") else "."
        )
        if file_path:
            self.certificate_path = file_path
            filename = os.path.basename(file_path)
            # Modern success feedback
            self.cert_status_label.config(text=f"📜 {filename}",
                                         fg=Colors.SUCCESS, bg=Colors.BG_CARD)
            self.animate_selection_feedback(self.cert_status_label)

    def animate_selection_feedback(self, label: tk.Label) -> None:
        """
        Animate file selection feedback.
        """
        original_bg = label.cget('bg')
        # Brief highlight animation
        label.config(bg=Colors.SUCCESS)
        self.root.after(150, lambda: label.config(bg=original_bg))

    def perform_login(self) -> None:
        """
        Perform automatic user login based on username and password, then manual challenge/response.
        """
        username = self.login_username_entry.get().strip()
        password = self.login_password_entry.get().strip()
        if not username:
            messagebox.showerror("Error", "Please enter your username!")
            return
        if not password:
            messagebox.showerror("Error", "Please enter your password!")
            return
        try:
            self.login_status_label.config(text="Authenticating...", fg=Colors.WARNING)
            self.root.update()
            user_data = self.db.get_user_by_username(username)
            if not user_data:
                messagebox.showerror("Error", f"User '{username}' not found!\nPlease register first or check your username.")
                self.login_status_label.config(text="User not found", fg=Colors.ERROR)
                return
            user_id = user_data[0]
            db_username = user_data[1]
            private_key_path = user_data[2]
            public_key_path = user_data[3]
            certificate_path = user_data[4]
            password_hash = user_data[8]
            salt = user_data[9]
            # Account lockout logic
            failed_attempts = user_data[10] if len(user_data) > 10 else 0
            lockout_until = user_data[11] if len(user_data) > 11 else None
            now = datetime.now(timezone.utc)
            if lockout_until:
                try:
                    lockout_dt = datetime.fromisoformat(lockout_until) if isinstance(lockout_until, str) else lockout_until
                except Exception:
                    lockout_dt = None
                if lockout_dt and lockout_dt > now:
                    unlock_time = lockout_dt.strftime('%Y-%m-%d %H:%M:%S')
                    messagebox.showerror("Account Locked", f"Too many failed login attempts.\nAccount is locked until {unlock_time}.")
                    self.login_status_label.config(text="Account locked", fg=Colors.ERROR)
                    return
            check_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100_000).hex()
            if not password_hash or not salt:
                messagebox.showerror("Error", "This user does not have a password set. Please register again.")
                self.login_status_label.config(text="No password set", fg=Colors.ERROR)
                return
            if check_hash != password_hash:
                # Increment failed_attempts
                with sqlite3.connect(self.db.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('SELECT failed_attempts FROM users WHERE username = ?', (username,))
                    fa = cursor.fetchone()[0] or 0
                    fa += 1
                    lockout_until_val = None
                    if fa >= 5:
                        lockout_until_val = (now + timedelta(minutes=1)).isoformat()
                        cursor.execute('UPDATE users SET failed_attempts = ?, lockout_until = ? WHERE username = ?', (fa, lockout_until_val, username))
                    else:
                        cursor.execute('UPDATE users SET failed_attempts = ? WHERE username = ?', (fa, username))
                    conn.commit()
                if fa >= 5:
                    messagebox.showerror("Account Locked", f"Too many failed login attempts.\nAccount is locked for 1 minute.")
                    self.login_status_label.config(text="Account locked", fg=Colors.ERROR)
                else:
                    messagebox.showerror("Error", f"Incorrect password! ({fa}/5 attempts)")
                    self.login_status_label.config(text=f"Incorrect password ({fa}/5)", fg=Colors.ERROR)
                return
            # Reset failed_attempts and lockout on success
            with sqlite3.connect(self.db.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('UPDATE users SET failed_attempts = 0, lockout_until = NULL WHERE username = ?', (username,))
                conn.commit()
            # Check certificate is CA-signed
            with open(certificate_path, 'rb') as f:
                cert_data = f.read()
            cert = x509.load_pem_x509_certificate(cert_data)
            if cert.issuer != self.ca_cert.subject:
                messagebox.showerror("Error", "Certificate is not signed by the CA!")
                self.login_status_label.config(text="Certificate not CA-signed", fg=Colors.ERROR)
                return
            # Save for challenge step
            self._pending_login = {
                'user_id': user_id,
                'username': username,
                'private_key_path': private_key_path,
                'certificate_path': certificate_path,
                'cert': cert
            }
            self.show_challenge_step()
        except Exception as e:
            self.login_status_label.config(text=f"Login failed: {str(e)}", fg=Colors.ERROR)
            messagebox.showerror("Error", f"Login failed: {str(e)}")
            if hasattr(self, 'key_status_label'):
                self.key_status_label.config(text="🔑 Private key: Not loaded", fg=Colors.TEXT_SECONDARY)
            if hasattr(self, 'cert_status_label'):
                self.cert_status_label.config(text="📜 Certificate: Not loaded", fg=Colors.TEXT_SECONDARY)

    def show_challenge_step(self) -> None:
        """
        Show the manual challenge/response step after password check.
        """
        # Clear login section
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        frame = tk.Frame(self.content_frame, bg=Colors.BG_CARD)
        frame.pack(pady=40, ipadx=20, ipady=20, fill='x', expand=True)
        tk.Label(frame, text="Manual Challenge/Response Authentication", font=(Fonts.PRIMARY, Fonts.HEADING, 'bold'), fg=Colors.TEXT_PRIMARY, bg=Colors.BG_CARD).pack(anchor='w', padx=20, pady=(20, 5))
        tk.Label(frame, text="To complete login, you must sign a random challenge file with your private key.", font=(Fonts.PRIMARY, Fonts.BODY), fg=Colors.TEXT_SECONDARY, bg=Colors.BG_CARD).pack(anchor='w', padx=20)
        # Generate challenge file
        challenge_bytes = os.urandom(32)
        challenge_dir = 'challenge'
        if not os.path.exists(challenge_dir):
            os.makedirs(challenge_dir)
        username = self._pending_login['username'] if hasattr(self, '_pending_login') and self._pending_login else 'user'
        self.challenge_file_path = os.path.join(challenge_dir, f"signetrix_challenge_{username}_{os.getpid()}.bin")
        with open(self.challenge_file_path, 'wb') as f:
            f.write(challenge_bytes)
        tk.Label(frame, text=f"Challenge file generated: {self.challenge_file_path}", font=(Fonts.SECONDARY, Fonts.SMALL), fg=Colors.INFO, bg=Colors.BG_CARD).pack(anchor='w', padx=20, pady=(10, 0))
        tk.Label(frame, text="Sign this file with your private key using an external tool or the built-in tool below.", font=(Fonts.PRIMARY, Fonts.SMALL), fg=Colors.TEXT_SECONDARY, bg=Colors.BG_CARD).pack(anchor='w', padx=20, pady=(0, 10))
        # Password entry for challenge signing
        tk.Label(frame, text="Password for Private Key:", font=(Fonts.PRIMARY, Fonts.BODY, 'bold'), fg=Colors.TEXT_PRIMARY, bg=Colors.BG_CARD).pack(anchor='w', padx=20, pady=(10, 2))
        challenge_pw_entry = tk.Entry(frame, show='*', font=(Fonts.PRIMARY, Fonts.BODY), width=25, relief='flat', bd=1, bg=Colors.BG_MAIN, fg=Colors.TEXT_PRIMARY)
        challenge_pw_entry.pack(anchor='w', padx=20, pady=(0, 10))
        # Optionally, add a built-in sign button
        sign_btn = tk.Button(frame, text="Sign Challenge with My Key", command=lambda: self.sign_challenge_with_key(challenge_pw_entry.get()), font=(Fonts.PRIMARY, Fonts.BODY, 'bold'), bg=Colors.BUTTON_SUCCESS, fg=Colors.TEXT_WHITE, relief='flat', bd=0, padx=20, pady=10, cursor='hand2')
        sign_btn.pack(anchor='w', padx=20, pady=(0, 10))
        # Upload signature file
        sig_path_var = tk.StringVar()
        def browse_sig():
            path = filedialog.askopenfilename(title="Select Challenge Signature File", filetypes=[("Signature files", "*.sig"), ("All files", "*.*")])
            if path:
                sig_path_var.set(path)
        tk.Label(frame, text="Upload the signature file:", font=(Fonts.PRIMARY, Fonts.BODY, 'bold'), fg=Colors.TEXT_PRIMARY, bg=Colors.BG_CARD).pack(anchor='w', padx=20, pady=(10, 0))
        sig_entry = tk.Entry(frame, textvariable=sig_path_var, font=(Fonts.PRIMARY, Fonts.BODY), width=40, relief='flat', bd=1, bg=Colors.BG_MAIN, fg=Colors.TEXT_PRIMARY)
        sig_entry.pack(anchor='w', padx=20, pady=(0, 0))
        tk.Button(frame, text="Browse", command=browse_sig, font=(Fonts.PRIMARY, Fonts.SMALL), bg=Colors.BUTTON_PRIMARY, fg=Colors.TEXT_WHITE, relief='flat', bd=0, padx=10, pady=5, cursor='hand2').pack(anchor='w', padx=20, pady=(5, 10))
        status_label = tk.Label(frame, text="", font=(Fonts.PRIMARY, Fonts.BODY), bg=Colors.BG_CARD)
        status_label.pack(anchor='w', padx=20, pady=(5, 0))
        def verify_challenge():
            sig_path = sig_path_var.get()
            if not sig_path or not os.path.exists(sig_path):
                status_label.config(text="Please select a valid signature file.", fg=Colors.ERROR)
                return
            try:
                with open(self.challenge_file_path, 'rb') as f:
                    challenge_data = f.read()
                with open(sig_path, 'rb') as f:
                    signature = f.read()
                cert = self._pending_login['cert']
                public_key = cert.public_key()
                public_key.verify(
                    signature,
                    challenge_data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                # Success: complete login
                self.current_user = self._pending_login['username']
                self.current_user_id = self._pending_login['user_id']
                self.is_logged_in = True
                self.private_key_path = self._pending_login['private_key_path']
                self.certificate_path = self._pending_login['certificate_path']
                self.db.update_last_login(self.current_user_id)
                self.db.log_audit_event(self.current_user_id, "USER_LOGIN", f"User {self.current_user} logged in (challenge/response)")
                self.user_status_label.config(text=f"● Logged in as: {self.current_user}", fg=Colors.SUCCESS)
                self.user_info_label.config(text="All features enabled")
                self.create_user_ui()
                self.update_system_status()
                messagebox.showinfo("Login Successful", f"Welcome back, {self.current_user}!\n\nChallenge/response authentication complete.")
            except Exception as e:
                status_label.config(text=f"Challenge verification failed: {str(e)}", fg=Colors.ERROR)
        tk.Button(frame, text="Verify Challenge Signature", command=verify_challenge, font=(Fonts.PRIMARY, Fonts.BODY, 'bold'), bg=Colors.BUTTON_PRIMARY, fg=Colors.TEXT_WHITE, relief='flat', bd=0, padx=20, pady=10, cursor='hand2').pack(anchor='w', padx=20, pady=20)
        tk.Button(frame, text="Cancel", command=self.create_initial_ui, font=(Fonts.PRIMARY, Fonts.SMALL), bg=Colors.BUTTON_DANGER, fg=Colors.TEXT_WHITE, relief='flat', bd=0, padx=10, pady=5, cursor='hand2').pack(anchor='w', padx=20, pady=(5, 10))

    def sign_challenge_with_key(self, password: str) -> None:
        """
        Sign the challenge file with the user's private key (if available) and save as .sig (decrypt with password).
        """
        try:
            if not hasattr(self, 'challenge_file_path') or not os.path.exists(self.challenge_file_path):
                messagebox.showerror("Error", "Challenge file not found.")
                return
            if not self._pending_login or not os.path.exists(self._pending_login['private_key_path']):
                messagebox.showerror("Error", "Private key not found.")
                return
            with open(self._pending_login['private_key_path'], "rb") as key_file:
                private_key = load_pem_private_key(key_file.read(), password=password.encode())
            with open(self.challenge_file_path, 'rb') as f:
                challenge_data = f.read()
            signature = private_key.sign(
                challenge_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            # Save signature file with username in name
            username = self._pending_login['username'] if self._pending_login else 'user'
            sig_path = os.path.join('challenge', f"signetrix_challenge_{username}_{os.getpid()}.sig")
            with open(sig_path, 'wb') as f:
                f.write(signature)
            messagebox.showinfo("Challenge Signed", f"Challenge signed successfully!\nSignature file: {sig_path}\nNow upload this file to complete login.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to sign challenge: {str(e)}")

    def perform_logout(self) -> None:
        """
        Perform user logout and return to initial UI.
        """
        # Enhanced logout confirmation
        result = messagebox.askyesno(
            "Confirm Logout",
            f"Are you sure you want to logout?\n\n"
            f"👤 Current user: {self.current_user}\n"
            f"🔐 You will need to login again to access Signetrix features.\n\n"
            f"Any unsaved work will be lost.",
            icon='question'
        )

        if result:
            try:
                # Log audit event before logout
                if hasattr(self, 'current_user_id') and self.current_user_id:
                    self.db.log_audit_event(self.current_user_id, "USER_LOGOUT",
                                          f"User {self.current_user} logged out successfully")

                # Delete challenge and signature files for this user
                try:
                    username = self.current_user if self.current_user else 'user'
                    challenge_dir = 'challenge'
                    challenge_file = os.path.join(challenge_dir, f"signetrix_challenge_{username}_{os.getpid()}.bin")
                    sig_file = os.path.join(challenge_dir, f"signetrix_challenge_{username}_{os.getpid()}.sig")
                    for fpath in [challenge_file, sig_file]:
                        if os.path.exists(fpath):
                            os.remove(fpath)
                except Exception:
                    pass

                # Reset state
                self.current_user = None
                self.current_user_id = None
                self.is_logged_in = False
                self.private_key_path = None
                self.certificate_path = None
                self.current_view = None

                # Update header UI if it exists
                if hasattr(self, 'user_status_label'):
                    self.user_status_label.config(text="● Not logged in", fg=Colors.ERROR)
                if hasattr(self, 'user_info_label'):
                    self.user_info_label.config(text="Please login to access features")

                # Clear content and return to initial UI
                for widget in self.content_frame.winfo_children():
                    widget.destroy()

                # Return to login screen
                self.create_initial_ui()
                self.update_system_status()

                # Success message
                messagebox.showinfo(
                    "Logout Successful",
                    f"✅ You have been logged out successfully!\n\n"
                    f"Thank you for using Signetrix.\n"
                    f"Login again to continue using Signetrix features.",
                    icon='info'
                )

            except Exception as e:
                messagebox.showerror("Logout Error", f"An error occurred during logout: {str(e)}")
                # Force logout anyway for security
                self.current_user = None
                self.is_logged_in = False
                for widget in self.content_frame.winfo_children():
                    widget.destroy()
                self.create_initial_ui()

    def select_document(self) -> None:
        """
        Select document to sign with modern feedback.
        """
        file_path = filedialog.askopenfilename(
            title="Select Document to Sign",
            filetypes=[("Text files", "*.txt"), ("PDF files", "*.pdf"), ("All files", "*.*")]
        )
        if file_path:
            self.document_path = file_path
            filename = os.path.basename(file_path)
            self.doc_path_label.config(text=f"📄 {filename}", fg=Colors.SUCCESS, bg=Colors.BG_MAIN)
            self.animate_selection_feedback(self.doc_path_label)

    def select_original_document(self) -> None:
        """
        Select original document for verification with modern feedback.
        """
        file_path = filedialog.askopenfilename(
            title="Select Original Document for Verification",
            filetypes=[("Text files", "*.txt"), ("PDF files", "*.pdf"), ("All files", "*.*")]
        )
        if file_path:
            self.orig_document_path = file_path
            filename = os.path.basename(file_path)
            self.orig_doc_label.config(text=f"📄 {filename}", fg=Colors.SUCCESS, bg=Colors.BG_MAIN)
            self.animate_selection_feedback(self.orig_doc_label)

    def select_signature_file(self) -> None:
        """
        Select signature file for verification with modern feedback.
        """
        file_path = filedialog.askopenfilename(
            title="Select Digital Signature File",
            filetypes=[("Signature files", "*.sig"), ("All files", "*.*")]
        )
        if file_path:
            self.signature_file_path = file_path
            filename = os.path.basename(file_path)
            self.sig_file_label.config(text=f"🔏 {filename}", fg=Colors.SUCCESS, bg=Colors.BG_MAIN)
            self.animate_selection_feedback(self.sig_file_label)

    def select_certificate_for_verification(self) -> None:
        """
        Select certificate file for verification with modern feedback.
        """
        file_path = filedialog.askopenfilename(
            title="Select Certificate File for Verification",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
        )
        if file_path:
            self.cert_verify_path = file_path
            filename = os.path.basename(file_path)
            self.cert_verify_label.config(text=f"📜 {filename}", fg=Colors.SUCCESS, bg=Colors.BG_MAIN)
            self.animate_selection_feedback(self.cert_verify_label)

    def verify_document(self) -> None:
        """
        Verify document signature with database integration (optimized for UX and performance).
        """
        if not hasattr(self, 'orig_document_path') or not self.orig_document_path:
            messagebox.showerror("Error", "Please select the original document!")
            return
        if not hasattr(self, 'signature_file_path') or not self.signature_file_path:
            messagebox.showerror("Error", "Please select the signature file!")
            return
        if not hasattr(self, 'cert_verify_path') or not self.cert_verify_path:
            messagebox.showerror("Error", "Please select the certificate file!")
            return

        def safe_label_update(label: Optional[tk.Label], **kwargs) -> None:
            try:
                if label and label.winfo_exists():
                    label.config(**kwargs)
            except Exception:
                pass

        def do_verification() -> None:
            try:
                # Show loading feedback
                self.root.after(0, lambda: safe_label_update(getattr(self, 'verify_status_label', None), text="Verifying document...", fg=Colors.WARNING))
                self.root.update_idletasks()

                # Robust file existence checks
                if not os.path.exists(self.orig_document_path):
                    raise FileNotFoundError(f"Original document not found: {self.orig_document_path}")
                if not os.path.exists(self.signature_file_path):
                    raise FileNotFoundError(f"Signature file not found: {self.signature_file_path}")
                if not os.path.exists(self.cert_verify_path):
                    raise FileNotFoundError(f"Certificate file not found: {self.cert_verify_path}")

                # Read original document
                with open(self.orig_document_path, 'rb') as f:
                    document_data = f.read()
                document_hash = hashlib.sha256(document_data).hexdigest()

                # Read signature
                with open(self.signature_file_path, 'rb') as f:
                    signature = f.read()

                # Read certificate and extract public key
                with open(self.cert_verify_path, 'rb') as f:
                    cert_data = f.read()
                try:
                    cert = x509.load_pem_x509_certificate(cert_data)
                except Exception:
                    try:
                        cert = x509.load_der_x509_certificate(cert_data)
                    except Exception as e:
                        raise ValueError("Certificate file is not a valid PEM or DER X.509 certificate.") from e
                public_key = cert.public_key()

                # Get certificate info for logging
                subject = cert.subject
                try:
                    common_name = subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                except Exception:
                    common_name = "Unknown"

                # Prepare verification details
                verification_details = {
                    'document_path': self.orig_document_path,
                    'signature_path': self.signature_file_path,
                    'certificate_path': self.cert_verify_path,
                    'document_hash': document_hash,
                    'signer_cn': common_name,
                    'verification_time': datetime.now().isoformat()
                }

                # Verify signature
                verification_result = False
                try:
                    public_key.verify(
                        signature,
                        document_data,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    verification_result = True
                    # UI feedback (thread-safe)
                    self.root.after(0, lambda: safe_label_update(getattr(self, 'verify_status_label', None), text="✓ Document signature is VALID!", fg=Colors.SUCCESS))
                    # Try to find the document in database and update verification count
                    document_id = self.db.find_document_by_hash(document_hash)
                    if document_id:
                        self.db.update_document_verification(document_id)
                        verification_details['document_id'] = document_id
                    self.db.add_verification_log(document_id or -1, self.current_user or "Verifier", True, json.dumps(verification_details))
                    self.db.log_audit_event(self.current_user_id or -1, "DOCUMENT_VERIFIED", f"Document verified: {self.orig_document_path}")
                    # Show signer and verification details in a messagebox
                    details_msg = (
                        f"✓ Document signature is VALID!\n\n"
                        f"Signer: {common_name}\n"
                        f"Certificate Subject: {subject}\n"
                        f"Document Hash: {document_hash[:16]}...\n"
                        f"Verification Time: {verification_details['verification_time']}\n"
                        f"\nThe document is authentic and has not been tampered with."
                    )
                    self.root.after(0, lambda: messagebox.showinfo(
                        "Verification Successful",
                        details_msg
                    ))
                except Exception as e:
                    self.root.after(0, lambda: safe_label_update(getattr(self, 'verify_status_label', None), text=f"Signature INVALID: {str(e)}", fg=Colors.ERROR))
                    document_id = self.db.find_document_by_hash(document_hash)
                    self.db.add_verification_log(document_id or -1, self.current_user or "Verifier", False, json.dumps(verification_details))
                    self.db.log_audit_event(self.current_user_id or -1, "DOCUMENT_VERIFY_ERROR", f"Verification failed: {str(e)}")
            except Exception as e:
                self.root.after(0, lambda: safe_label_update(getattr(self, 'verify_status_label', None), text=f"Verification failed: {str(e)}", fg=Colors.ERROR))

        threading.Thread(target=do_verification, daemon=True).start()

    def update_system_status(self) -> None:
        """
        Update system status information.
        """
        try:
            # Get statistics from database
            stats = self.db.get_user_statistics()
            info_parts = [
                f"Users: {stats['total_users']}",
                f"Documents: {stats['total_documents']}",
                f"Verifications: {stats['total_verifications']}"
            ]
            if hasattr(self, 'system_info_label'):
                self.system_info_label.config(text=" | ".join(info_parts))
        except Exception:
            pass

    def show_use_case_window(self) -> None:
        """
        Show a window describing the application's use case in detail.
        """
        use_case_text = (
            "Signetrix: Secure Digital Document Signing and Verification\n\n"
            "Signetrix is designed for secure, legally binding digital document workflows.\n\n"
            "Key Use Case:\n"
            "- Digital signing of contracts, agreements, and sensitive documents for businesses, legal, and government sectors.\n"
            "- Each user receives a unique, CA-signed digital certificate and encrypted private key.\n"
            "- Documents are signed with strong cryptography, ensuring authenticity, integrity, and non-repudiation.\n"
            "- Recipients can verify signatures and the signer's certificate, preventing forgery and tampering.\n"
            "- All actions are logged for audit and compliance.\n\n"
            "Why it matters:\n"
            "- Eliminates paper-based signatures and manual verification.\n"
            "- Prevents document fraud and unauthorized access.\n"
            "- Provides legal evidence of signing and verification.\n"
            "- Enables secure, efficient, and compliant digital workflows.\n\n"
            "Example Applications:\n"
            "- Legal contract execution\n"
            "- Business agreements\n"
            "- Government forms\n"
            "- Healthcare records\n"
            "- Secure file sharing\n"
        )
        win = tk.Toplevel(self.root)
        win.title("Signetrix Use Case")
        win.geometry("600x500")
        win.configure(bg=Colors.BG_MAIN)
        tk.Label(win, text="Signetrix - Application Use Case", font=(Fonts.PRIMARY, 18, 'bold'), fg=Colors.PRIMARY_DARK, bg=Colors.BG_MAIN).pack(pady=(20, 10))
        text_widget = tk.Text(win, wrap='word', font=(Fonts.PRIMARY, 12), bg=Colors.BG_MAIN, fg=Colors.TEXT_PRIMARY, relief='flat', bd=0)
        text_widget.insert('1.0', use_case_text)
        text_widget.config(state='disabled')
        text_widget.pack(fill='both', expand=True, padx=20, pady=10)

# =====================
# Application Entry Point
# =====================

def main() -> None:
    """
    Main function to run the PKI system.
    """
    root = tk.Tk()
    app = PKISystem(root)
    root.mainloop()

if __name__ == "__main__":
    main()






