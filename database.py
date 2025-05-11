import sqlite3
from datetime import datetime
import secrets
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def init_db():
    """Initialize the SQLite database and create the encrypted_keys table if it doesn't exist."""
    conn = sqlite3.connect("cyphersafe.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS encrypted_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            password TEXT UNIQUE,
            salt BLOB,
            timestamp TEXT
        )
    """)
    conn.commit()
    conn.close()

def get_key_from_password(password: str) -> bytes:
    """Retrieve or generate a key for the given password."""
    conn = sqlite3.connect("cyphersafe.db")
    cursor = conn.cursor()
    cursor.execute("SELECT salt FROM encrypted_keys WHERE password = ?", (password,))
    row = cursor.fetchone()
    conn.close()

    if row:
        salt = row[0]
        key = derive_key(password, salt)
    else:
        salt = secrets.token_bytes(16)
        key = derive_key(password, salt)
        conn = sqlite3.connect("cyphersafe.db")
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO encrypted_keys (password, salt, timestamp)
            VALUES (?, ?, ?)
        """, (password, salt, datetime.now().isoformat()))
        conn.commit()
        conn.close()

    return key

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a cryptographic key from a password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())[:16]
