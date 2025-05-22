import streamlit as st
import sqlite3
import cv2
import numpy as np
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet
from base64 import b64encode, b64decode
from io import BytesIO
from datetime import datetime
import secrets
from PIL import Image

# Initialize SQLite database
DB_PATH = "cyphersafe.db"

def init_db():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS encrypted_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_name TEXT,
                algorithm TEXT,
                salt BLOB,
                iv BLOB,
                encrypted_key BLOB,
                timestamp TEXT
            )
        """)
        conn.commit()
    except sqlite3.Error as e:
        st.error(f"Database initialization error: {e}")
    finally:
        conn.close()

# Derive a cryptographic key from a password
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# AES-GCM encryption
def aes_encrypt(data: bytes, key: bytes) -> (bytes, bytes):
    iv = secrets.token_bytes(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return iv, ciphertext

# AES-GCM decryption
def aes_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()

# Fernet encryption
def fernet_encrypt(data: bytes, key: bytes) -> bytes:
    fernet = Fernet(key)
    return fernet.encrypt(data)

# Fernet decryption
def fernet_decrypt(data: bytes, key: bytes) -> bytes:
    fernet = Fernet(key)
    return fernet.decrypt(data)

# DES encryption
def des_encrypt(data: bytes, key: bytes) -> (bytes, bytes):
    iv = secrets.token_bytes(8)
    cipher = Cipher(algorithms.TripleDES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return iv, ciphertext

# DES decryption
def des_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.TripleDES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()

# Blur image
def blur_image(image_data: bytes, blur_strength: int) -> bytes:
    image = Image.open(BytesIO(image_data))
    image_np = np.array(image)
    blurred = cv2.GaussianBlur(image_np, (blur_strength, blur_strength), 0)
    blurred_image = Image.fromarray(blurred)
    output = BytesIO()
    blurred_image.save(output, format=image.format)
    return output.getvalue()

# Insert metadata into the database
def db_insert(file_name: str, algorithm: str, salt: bytes, iv: bytes, encrypted_key: bytes):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO encrypted_files (file_name, algorithm, salt, iv, encrypted_key, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (file_name, algorithm, salt, iv, encrypted_key, datetime.now().isoformat()))
    conn.commit()
    conn.close()

# Retrieve metadata from the database
def db_retrieve():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT file_name, algorithm, timestamp FROM encrypted_files")
    rows = cursor.fetchall()
    conn.close()
    return rows

# Check if a password is associated with a file
def get_existing_key(file_name: str) -> (bytes, bytes):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT salt, encrypted_key FROM encrypted_files WHERE file_name = ?", (file_name,))
    row = cursor.fetchone()
    conn.close()
    return row if row else None

def password_strength(password: str):
    """Return a score (0-4) and message for password strength."""
    import re
    score = 0
    if len(password) >= 8:
        score += 1
    if re.search(r"[A-Z]", password):
        score += 1
    if re.search(r"[a-z]", password):
        score += 1
    if re.search(r"\d", password):
        score += 1
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
    if score == 0:
        msg = "Very Weak"
    elif score == 1:
        msg = "Weak"
    elif score == 2:
        msg = "Moderate"
    elif score == 3:
        msg = "Strong"
    else:
        msg = "Very Strong"
    return min(score, 4), msg

# Main Streamlit UI
def main():
    st.title("CypherSafe - Password-Based Encryption System")
    st.sidebar.title("Options")
    mode = st.sidebar.selectbox("Select Mode", ["Encrypt", "Decrypt", "View Database"])

    try:
        init_db()
    except Exception as e:
        st.error(f"Failed to initialize database: {e}")
        return

    if mode == "Encrypt":
        st.header("Encrypt a File")
        uploaded_file = st.file_uploader("Upload a File", type=None)
        password = st.text_input("Enter Password", type="password", key="encrypt_password")
        # Password strength tester
        if password:
            score, msg = password_strength(password)
            st.progress(score / 4)
            st.info(f"Password Strength: {msg}")
        algorithm = st.selectbox("Select Algorithm", ["AES-GCM", "Fernet", "DES"])
        blur_option = st.checkbox("Apply Blur (Images Only)")
        blur_strength = st.slider("Blur Strength", 5, 99, 15, step=2) if blur_option else None

        if st.button("Encrypt"):
            if not uploaded_file or not password:
                st.error("Please upload a file and enter a password.")
                return

            if len(password) < 8:
                st.warning("Password is weak. Use at least 8 characters.")
                return

            try:
                file_content = uploaded_file.read()
                existing_key_data = get_existing_key(uploaded_file.name)

                if existing_key_data:
                    salt, encrypted_key = existing_key_data
                    key = derive_key(password, salt)
                    st.info("Using existing password and key for this file.")
                else:
                    salt = secrets.token_bytes(16)
                    key = derive_key(password, salt)
                    st.success("New password and key generated for this file.")

                if algorithm == "AES-GCM":
                    iv, encrypted_data = aes_encrypt(file_content, key)
                elif algorithm == "Fernet":
                    fernet_key = b64encode(key)
                    encrypted_data = fernet_encrypt(file_content, fernet_key)
                    iv = b""  # Fernet does not use IV
                elif algorithm == "DES":
                    iv, encrypted_data = des_encrypt(file_content, key[:24])  # DES requires 24-byte key
                else:
                    st.error("Unsupported algorithm.")
                    return

                if blur_option and uploaded_file.type.startswith("image/"):
                    encrypted_data = blur_image(encrypted_data, blur_strength)

                db_insert(uploaded_file.name, algorithm, salt, iv, encrypted_data)
                st.success("File encrypted successfully.")
                st.download_button("Download Encrypted File", data=BytesIO(encrypted_data), file_name=f"encrypted_{uploaded_file.name}")
            except Exception as e:
                st.error(f"Encryption failed: {e}")

    elif mode == "Decrypt":
        st.header("Decrypt a File")
        uploaded_file = st.file_uploader("Upload an Encrypted File", type=None)
        password = st.text_input("Enter Password", type="password", key="decrypt_password")
        # Password strength tester (optional for decryption, but shown for user feedback)
        if password:
            score, msg = password_strength(password)
            st.progress(score / 4)
            st.info(f"Password Strength: {msg}")
        algorithm = st.selectbox("Select Algorithm", ["AES-GCM", "Fernet", "DES"])

        if st.button("Decrypt"):
            if not uploaded_file or not password:
                st.error("Please upload a file and enter a password.")
                return

            try:
                file_content = uploaded_file.read()
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute("SELECT salt, iv, encrypted_key FROM encrypted_files WHERE file_name = ?", (uploaded_file.name,))
                row = cursor.fetchone()
                conn.close()

                if not row:
                    st.error("File metadata not found in the database.")
                    return

                salt, iv, encrypted_key = row
                key = derive_key(password, salt)

                if algorithm == "AES-GCM":
                    decrypted_data = aes_decrypt(file_content, key, iv)
                elif algorithm == "Fernet":
                    fernet_key = b64encode(key)
                    decrypted_data = fernet_decrypt(file_content, fernet_key)
                elif algorithm == "DES":
                    decrypted_data = des_decrypt(file_content, key[:24], iv)
                else:
                    st.error("Unsupported algorithm.")
                    return

                st.success("File decrypted successfully.")
                st.download_button("Download Decrypted File", data=BytesIO(decrypted_data), file_name=f"decrypted_{uploaded_file.name}")
            except Exception as e:
                st.error(f"Decryption failed: {e}")

    elif mode == "View Database":
        st.header("Database Contents")
        try:
            rows = db_retrieve()
            st.dataframe(rows)
            st.download_button("Download Metadata as CSV", data="\n".join([",".join(map(str, row)) for row in rows]), file_name="metadata.csv")
        except Exception as e:
            st.error(f"Failed to retrieve database contents: {e}")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        st.error(f"An unexpected error occurred: {e}")
