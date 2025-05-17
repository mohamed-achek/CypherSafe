import streamlit as st
from algorithms import *
from base64 import b64encode, b64decode
import os
from io import BytesIO
from PIL import Image  # Import for image processing
from password_system import main as password_system_main  # Import the password system
import sqlite3
import secrets
from datetime import datetime
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet  # Import Fernet for symmetric encryption
from modes.im_vid import partial_encrypt_image, partial_decrypt_image

# Set the page configuration with a custom icon
st.set_page_config(page_title="CypherSafe", page_icon="Assets/white_on_trans.png")

def pixelate_image(image_data):
    """Apply pixelation effect to an image."""
    image = Image.open(BytesIO(image_data))
    small = image.resize((image.width // 10, image.height // 10), resample=Image.BILINEAR)
    pixelated = small.resize(image.size, Image.NEAREST)
    output = BytesIO()
    pixelated.save(output, format=image.format)
    return output.getvalue()

def get_key_from_password(password: str, truncate_to: int = 32) -> bytes:
    """Retrieve or generate a key for the given password, truncated to the required length."""
    conn = sqlite3.connect("cyphersafe.db")
    cursor = conn.cursor()
    cursor.execute("SELECT salt FROM encrypted_keys WHERE password = ?", (password,))
    row = cursor.fetchone()  # <-- fix: use cursor.fetchone(), not conn.fetchone()
    conn.close()

    if row:
        salt = row[0]
        full_key = derive_key(password, salt)  # Derive the full 32-byte key
        st.info("Using existing key associated with this password.")
    else:
        salt = secrets.token_bytes(16)
        full_key = derive_key(password, salt)  # Generate a new full 32-byte key
        st.success("New key generated for this password.")
        # Insert the new key into the database
        conn = sqlite3.connect("cyphersafe.db")
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO encrypted_keys (password, salt, timestamp)
            VALUES (?, ?, ?)
        """, (password, salt, datetime.now().isoformat()))
        conn.commit()
        conn.close()

    return full_key[:truncate_to]  # Truncate the key to the required length

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a cryptographic key from a password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Derive a 32-byte key
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

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

def main():
    # Initialize the database
    init_db()

    # Display the logo at the top of the app
    try:
        st.image("Assets/white_on_trans.png", width=200)  # Adjust the width as needed
    except FileNotFoundError:
        st.warning("Logo not found. Ensure 'Assets/original.png' exists.")
    st.title("CypherSafe")

    st.sidebar.title("Navigation")
    try:
        st.sidebar.image("Assets/algo.png", width=200)  # Adjust the width as needed
    except FileNotFoundError:
        st.warning("Sidebar image not found. Ensure 'Assets/algo.png' exists.")

    # Completely separate navigation for image encryption
    page = st.sidebar.radio(
        "Go to",
        [
            "Algorithms",
            "Image and Video Encryption"
        ],
        key="main_page"
    )

    if page == "Algorithms":
        mode = st.sidebar.selectbox(
            "Select Mode",
            [
                "Symmetric",
                "Asymmetric",
                "Hashing",
                "Digital Signature"
            ],
            key="main_mode"
        )

        if mode == "Symmetric":
            st.header("Symmetric Encryption/Decryption")
            tab_aes, tab_fernet, tab_des = st.tabs(["AES", "Fernet", "DES"])

            # AES Tab
            with tab_aes:
                st.subheader("AES (Advanced Encryption Standard)")
                uploaded_file = st.file_uploader("Upload a File (Text, Image, or Video)", type=["txt", "png", "jpg", "jpeg", "mp4"])
                
                # Use a temporary variable to handle the key
                if "aes_key_temp" not in st.session_state:
                    st.session_state["aes_key_temp"] = ""

                key = st.text_input("Key (16 bytes)", value=st.session_state["aes_key_temp"], type="password", key="aes_key")
                
                if st.button("Generate AES Key"):
                    password = st.text_input("Enter Password for Key Generation", type="password", key="aes_password")
                    if password:
                        try:
                            generated_key = get_key_from_password(password, truncate_to=16)  # Truncate to 16 bytes for AES
                            st.session_state["aes_key_temp"] = b64encode(generated_key).decode()  # Update the temporary variable
                            st.success("AES Key generated successfully.")
                        except Exception as e:
                            st.error(f"Error: {e}")
                    else:
                        st.error("Please enter a password to generate a key.")

                operation = st.selectbox("Operation", ["Encrypt", "Decrypt"], key="aes_operation")

                if st.button("Execute AES"):
                    try:
                        if uploaded_file is None:
                            st.error("Please upload a file.")
                        else:
                            # Decode the Base64 key and validate its length
                            decoded_key = b64decode(key.encode())
                            if len(decoded_key) != 16:
                                st.error(f"Invalid Key Length: Key must be exactly 16 bytes. Current length is {len(decoded_key)} bytes.")
                            else:
                                file_content = uploaded_file.read()
                                if operation == "Encrypt":
                                    result = aes_encrypt(file_content, decoded_key)
                                    file_name = f"encrypted_{uploaded_file.name}"
                                    
                                    # Apply pixelation if the file is an image
                                    if uploaded_file.type.startswith("image/"):
                                        result = pixelate_image(file_content)
                                else:
                                    result = aes_decrypt(file_content, decoded_key)
                                    file_name = f"decrypted_{uploaded_file.name}"
                                
                                # Save the result as a downloadable file
                                st.download_button(
                                    label="Download Result",
                                    data=BytesIO(result if isinstance(result, bytes) else result.encode()),
                                    file_name=file_name,
                                    mime="application/octet-stream"
                                )
                    except Exception as e:
                        st.error(f"Error: {e}")

            # Fernet Tab
            with tab_fernet:
                st.subheader("Fernet (Symmetric Encryption Using AES)")
                uploaded_file = st.file_uploader("Upload a File (Text, Image, or Video)", type=["txt", "png", "jpg", "jpeg", "mp4"], key="fernet_file")
                
                # Use a temporary variable to handle the key
                if "fernet_key_temp" not in st.session_state:
                    st.session_state["fernet_key_temp"] = ""

                key = st.text_input("Key", value=st.session_state["fernet_key_temp"], type="password", key="fernet_key")
                
                if st.button("Generate Fernet Key"):
                    password = st.text_input("Enter Password for Key Generation", type="password", key="fernet_password")
                    if password:
                        try:
                            fernet_key = get_key_from_password(password)  # Use the full 32-byte key for Fernet
                            st.session_state["fernet_key_temp"] = b64encode(fernet_key).decode()  # Update the temporary variable
                            st.success("Fernet Key generated successfully.")
                        except Exception as e:
                            st.error(f"Error: {e}")
                    else:
                        st.error("Please enter a password to generate a key.")

                operation = st.selectbox("Operation", ["Encrypt", "Decrypt"], key="fernet_operation")

                if st.button("Execute Fernet"):
                    try:
                        if uploaded_file is None:
                            st.error("Please upload a file.")
                        else:
                            file_content = uploaded_file.read()
                            fernet = Fernet(key.encode())
                            if operation == "Encrypt":
                                result = fernet.encrypt(file_content)
                                file_name = f"encrypted_{uploaded_file.name}"
                            else:
                                result = fernet.decrypt(file_content)
                                file_name = f"decrypted_{uploaded_file.name}"
                            
                            # Save the result as a downloadable file
                            st.download_button(
                                label="Download Result",
                                data=BytesIO(result),
                                file_name=file_name,
                                mime="application/octet-stream"
                            )
                    except Exception as e:
                        st.error(f"Error: {e}")

            # DES Tab
            with tab_des:
                st.subheader("DES (Data Encryption Standard)")
                uploaded_file = st.file_uploader("Upload a File (Text, Image, or Video)", type=["txt", "png", "jpg", "jpeg", "mp4"], key="des_file")
                
                # Use a temporary variable to handle the key
                if "des_key_temp" not in st.session_state:
                    st.session_state["des_key_temp"] = ""

                key = st.text_input("Key (8 bytes)", value=st.session_state["des_key_temp"], type="password", key="des_key_input")
                
                if st.button("Generate DES Key"):
                    password = st.text_input("Enter Password for Key Generation", type="password", key="des_password")
                    if password:
                        try:
                            des_key = get_key_from_password(password, truncate_to=8)  # Truncate to 8 bytes for DES
                            if len(des_key) != 8:
                                st.error("Generated key is not 8 bytes. Please try again.")
                            else:
                                st.session_state["des_key_temp"] = b64encode(des_key).decode()  # Update the temporary variable
                                st.success("DES Key generated successfully.")
                        except Exception as e:
                            st.error(f"Error: {e}")
                    else:
                        st.error("Please enter a password to generate a key.")

                operation = st.selectbox("Operation", ["Encrypt", "Decrypt"], key="des_operation")

                if st.button("Execute DES"):
                    try:
                        if uploaded_file is None:
                            st.error("Please upload a file.")
                        else:
                            decoded_key = b64decode(key.encode())
                            if len(decoded_key) != 8:
                                st.error(f"Invalid Key Length: Key must be exactly 8 bytes. Current length is {len(decoded_key)} bytes.")
                            else:
                                file_content = uploaded_file.read()
                                if operation == "Encrypt":
                                    result = des_encrypt(file_content, decoded_key)
                                    file_name = f"encrypted_{uploaded_file.name}"
                                else:
                                    result = des_decrypt(file_content, decoded_key)
                                    file_name = f"decrypted_{uploaded_file.name}"
                                
                                # Save the result as a downloadable file
                                st.download_button(
                                    label="Download Result",
                                    data=BytesIO(result if isinstance(result, bytes) else result.encode()),
                                    file_name=file_name,
                                    mime="application/octet-stream"
                                )
                    except Exception as e:
                        st.error(f"Error: {e}")

        elif mode == "Asymmetric":
            st.header("Asymmetric Encryption/Decryption")
            tab_rsa, tab_ecc = st.tabs(["RSA", "ECC"])

            # RSA Tab
            with tab_rsa:
                st.subheader("RSA (Rivest-Shamir-Adleman)")
                operation = st.selectbox("Operation", ["Generate Keys", "Encrypt", "Decrypt"], key="rsa_operation")

                if operation == "Generate Keys":
                    if "rsa_private_key" not in st.session_state:
                        st.session_state["rsa_private_key"] = ""
                    if "rsa_public_key" not in st.session_state:
                        st.session_state["rsa_public_key"] = ""

                    if st.button("Generate RSA Keys"):
                        try:
                            private_key_pem, public_key_pem = generate_rsa_keys()
                            st.session_state["rsa_private_key"] = private_key_pem
                            st.session_state["rsa_public_key"] = public_key_pem
                            st.success("RSA keys generated successfully.")
                        except Exception as e:
                            st.error(f"Error generating RSA keys: {e}")

                    col1, col2 = st.columns(2)

                    with col1:
                        st.text_area("Private Key", st.session_state["rsa_private_key"], height=150, key="rsa_private_key_area")
                        st.download_button(
                            label="Download Private Key",
                            data=st.session_state["rsa_private_key"],
                            file_name="rsa_private_key.pem",
                            mime="application/x-pem-file"
                        )

                    with col2:
                        st.text_area("Public Key", st.session_state["rsa_public_key"], height=150, key="rsa_public_key_area")
                        st.download_button(
                            label="Download Public Key",
                            data=st.session_state["rsa_public_key"],
                            file_name="rsa_public_key.pem",
                            mime="application/x-pem-file"
                        )

                elif operation == "Encrypt":
                    uploaded_file = st.file_uploader("Upload File to Encrypt (Text, Image, or Video)", type=["txt", "png", "jpg", "jpeg", "mp4"], key="rsa_encrypt_file")
                    uploaded_public_key = st.file_uploader("Upload Public Key", type=["pem"], key="rsa_upload_public_key")
                    public_key_pem = None
                    if uploaded_public_key:
                        public_key_pem = uploaded_public_key.read().decode()
                    else:
                        public_key_pem = st.text_area("Public Key", key="rsa_public_key")

                    if st.button("Encrypt RSA"):
                        try:
                            if not uploaded_file:
                                st.error("Please upload a file to encrypt.")
                            elif not public_key_pem:
                                st.error("Please provide or upload a public key.")
                            else:
                                file_content = uploaded_file.read()
                                result = rsa_encrypt(file_content.decode(), public_key_pem)
                                st.text_area("Result", result, height=100)
                                st.download_button(
                                    label="Download Encrypted File",
                                    data=result.encode(),
                                    file_name=f"encrypted_{uploaded_file.name}",
                                    mime="application/octet-stream"
                                )
                        except Exception as e:
                            st.error(f"Error encrypting with RSA: {e}")

                elif operation == "Decrypt":
                    uploaded_file = st.file_uploader("Upload File to Decrypt (Text, Image, or Video)", type=["txt", "png", "jpg", "jpeg", "mp4"], key="rsa_decrypt_file")
                    uploaded_private_key = st.file_uploader("Upload Private Key", type=["pem"], key="rsa_upload_private_key")
                    private_key_pem = None
                    if uploaded_private_key:
                        private_key_pem = uploaded_private_key.read().decode()
                    else:
                        private_key_pem = st.text_area("Private Key", key="rsa_private_key")

                    if st.button("Decrypt RSA"):
                        try:
                            if not uploaded_file:
                                st.error("Please upload a file to decrypt.")
                            elif not private_key_pem:
                                st.error("Please provide or upload a private key.")
                            else:
                                file_content = uploaded_file.read()
                                result = rsa_decrypt(file_content.decode(), private_key_pem)
                                st.text_area("Result", result, height=100)
                                st.download_button(
                                    label="Download Decrypted File",
                                    data=result.encode(),
                                    file_name=f"decrypted_{uploaded_file.name}",
                                    mime="application/octet-stream"
                                )
                        except Exception as e:
                            st.error(f"Error decrypting with RSA: {e}")

            # ECC Tab
            with tab_ecc:
                st.subheader("ECC (Elliptic Curve Cryptography)")
                operation = st.selectbox("Operation", ["Generate Keys", "Encrypt", "Decrypt"], key="ecc_operation")

                if operation == "Generate Keys":
                    if "ecc_private_key" not in st.session_state:
                        st.session_state["ecc_private_key"] = ""
                    if "ecc_public_key" not in st.session_state:
                        st.session_state["ecc_public_key"] = ""

                    if st.button("Generate ECC Keys"):
                        try:
                            private_key_pem, public_key_pem = generate_ecc_keys()
                            st.session_state["ecc_private_key"] = private_key_pem
                            st.session_state["ecc_public_key"] = public_key_pem
                            st.success("ECC keys generated successfully.")
                        except Exception as e:
                            st.error(f"Error generating ECC keys: {e}")

                    col1, col2 = st.columns(2)

                    with col1:
                        st.text_area("Private Key", st.session_state["ecc_private_key"], height=150, key="ecc_private_key_area")
                        st.download_button(
                            label="Download Private Key",
                            data=st.session_state["ecc_private_key"],
                            file_name="ecc_private_key.pem",
                            mime="application/x-pem-file"
                        )

                    with col2:
                        st.text_area("Public Key", st.session_state["ecc_public_key"], height=150, key="ecc_public_key_area")
                        st.download_button(
                            label="Download Public Key",
                            data=st.session_state["ecc_public_key"],
                            file_name="ecc_public_key.pem",
                            mime="application/x-pem-file"
                        )

                elif operation == "Encrypt":
                    uploaded_file = st.file_uploader("Upload File to Encrypt (Text, Image, or Video)", type=["txt", "png", "jpg", "jpeg", "mp4"], key="ecc_encrypt_file")
                    uploaded_public_key = st.file_uploader("Upload Public Key", type=["pem"], key="ecc_upload_public_key")
                    public_key_pem = None
                    if uploaded_public_key:
                        public_key_pem = uploaded_public_key.read().decode()
                    else:
                        public_key_pem = st.text_area("Public Key", key="ecc_public_key")

                    if st.button("Encrypt ECC"):
                        try:
                            if not uploaded_file:
                                st.error("Please upload a file to encrypt.")
                            elif not public_key_pem:
                                st.error("Please provide or upload a public key.")
                            else:
                                file_content = uploaded_file.read()
                                result = ecc_encrypt(file_content.decode(), public_key_pem)
                                st.text_area("Result", result, height=100)
                                st.download_button(
                                    label="Download Encrypted File",
                                    data=result.encode(),
                                    file_name=f"encrypted_{uploaded_file.name}",
                                    mime="application/octet-stream"
                                )
                        except Exception as e:
                            st.error(f"Error encrypting with ECC: {e}")

                elif operation == "Decrypt":
                    uploaded_file = st.file_uploader("Upload File to Decrypt (Text, Image, or Video)", type=["txt", "png", "jpg", "jpeg", "mp4"], key="ecc_decrypt_file")
                    uploaded_private_key = st.file_uploader("Upload Private Key", type=["pem"], key="ecc_upload_private_key")
                    private_key_pem = None
                    if uploaded_private_key:
                        private_key_pem = uploaded_private_key.read().decode()
                    else:
                        private_key_pem = st.text_area("Private Key", key="ecc_private_key")

                    if st.button("Decrypt ECC"):
                        try:
                            if not uploaded_file:
                                st.error("Please upload a file to decrypt.")
                            elif not private_key_pem:
                                st.error("Please provide or upload a private key.")
                            else:
                                file_content = uploaded_file.read()
                                result = ecc_decrypt(file_content.decode(), private_key_pem)
                                st.text_area("Result", result, height=100)
                                st.download_button(
                                    label="Download Decrypted File",
                                    data=result.encode(),
                                    file_name=f"decrypted_{uploaded_file.name}",
                                    mime="application/octet-stream"
                                )
                        except Exception as e:
                            st.error(f"Error decrypting with ECC: {e}")

        elif mode == "Hashing":
            st.header("Hashing")
            tab_sha256, tab_sha512, tab_md5 = st.tabs(["SHA-256", "SHA-512", "MD5"])

            # SHA-256 Tab
            with tab_sha256:
                st.subheader("SHA-256 (Secure Hash Algorithm 256-bit)")
                uploaded_file = st.file_uploader("Upload a File (Text, Image, or Video)", type=["txt", "png", "jpg", "jpeg", "mp4"], key="sha256_file")
                if st.button("Hash with SHA-256"):
                    try:
                        if uploaded_file is None:
                            st.error("Please upload a file.")
                        else:
                            file_content = uploaded_file.read()
                            result = sha256_hash(file_content.decode())
                            st.text_area("Hash Value (SHA-256)", result, height=100)
                            
                            # Provide download link for the result
                            st.download_button(
                                label="Download Result",
                                data=BytesIO(result.encode() if isinstance(result, str) else result),
                                file_name="hash_sha256.txt",
                                mime="application/octet-stream"
                            )
                    except Exception as e:
                        st.error(f"Error: {e}")

            # SHA-512 Tab
            with tab_sha512:
                st.subheader("SHA-512 (Secure Hash Algorithm 512-bit)")
                uploaded_file = st.file_uploader("Upload a File (Text, Image, or Video)", type=["txt", "png", "jpg", "jpeg", "mp4"], key="sha512_file")
                if st.button("Hash with SHA-512"):
                    try:
                        if uploaded_file is None:
                            st.error("Please upload a file.")
                        else:
                            file_content = uploaded_file.read()
                            result = sha512_hash(file_content.decode())
                            st.text_area("Hash Value (SHA-512)", result, height=100)
                            
                            # Provide download link for the result
                            st.download_button(
                                label="Download Result",
                                data=BytesIO(result.encode() if isinstance(result, str) else result),
                                file_name="hash_sha512.txt",
                                mime="application/octet-stream"
                            )
                    except Exception as e:
                        st.error(f"Error: {e}")

            # MD5 Tab
            with tab_md5:
                st.subheader("MD5 (Less Secure)")
                uploaded_file = st.file_uploader("Upload a File (Text, Image, or Video)", type=["txt", "png", "jpg", "jpeg", "mp4"], key="md5_file")
                if st.button("Hash with MD5"):
                    try:
                        if uploaded_file is None:
                            st.error("Please upload a file.")
                        else:
                            file_content = uploaded_file.read()
                            result = md5_hash(file_content.decode())
                            st.text_area("Hash Value (MD5)", result, height=100)
                            
                            # Provide download link for the result
                            st.download_button(
                                label="Download Result",
                                data=BytesIO(result.encode() if isinstance(result, str) else result),
                                file_name="hash_md5.txt",
                                mime="application/octet-stream"
                            )
                    except Exception as e:
                        st.error(f"Error: {e}")

        elif mode == "Digital Signature":
            st.header("Digital Signature")
            tab_rsa_sign, tab_ecc_sign, tab_verify = st.tabs(["RSA Digital Signature", "ECC Digital Signature", "Verification of Digital Signature"])

            # RSA Digital Signature Tab
            with tab_rsa_sign:
                st.subheader("RSA Digital Signature")
                if "rsa_sign_private_key" not in st.session_state:
                    st.session_state["rsa_sign_private_key"] = ""

                if st.button("Generate RSA Private Key for Signing"):
                    try:
                        private_key_pem, _ = generate_rsa_keys()
                        st.session_state["rsa_sign_private_key"] = private_key_pem
                        st.success("RSA private key for signing generated successfully.")
                    except Exception as e:
                        st.error(f"Error generating RSA private key: {e}")

                st.text_area("Private Key (PEM Format)", st.session_state["rsa_sign_private_key"], height=150, key="rsa_sign_private_key_area")
                st.download_button(
                    label="Download Private Key",
                    data=st.session_state["rsa_sign_private_key"],
                    file_name="rsa_sign_private_key.pem",
                    mime="application/x-pem-file"
                )
                uploaded_file = st.file_uploader("Upload File to Sign (Text, Image, or Video)", type=["txt", "png", "jpg", "jpeg", "mp4"], key="rsa_sign_file")

                if st.button("Sign with RSA"):
                    try:
                        if not st.session_state["rsa_sign_private_key"]:
                            st.error("Please generate or provide a private key.")
                        elif not uploaded_file:
                            st.error("Please upload a file to sign.")
                        else:
                            file_content = uploaded_file.read()
                            signature = rsa_sign(file_content, st.session_state["rsa_sign_private_key"])
                            st.text_area("Digital Signature (RSA)", signature, height=100)
                            st.download_button(
                                label="Download Signature",
                                data=BytesIO(signature.encode()),
                                file_name="rsa_signature.txt",
                                mime="application/octet-stream"
                            )
                    except Exception as e:
                        st.error(f"Error signing with RSA: {e}")

            # ECC Digital Signature Tab
            with tab_ecc_sign:
                st.subheader("ECC Digital Signature")
                if "ecc_sign_private_key" not in st.session_state:
                    st.session_state["ecc_sign_private_key"] = ""

                if st.button("Generate ECC Private Key for Signing"):
                    try:
                        private_key_pem, _ = generate_ecc_keys()
                        st.session_state["ecc_sign_private_key"] = private_key_pem
                        st.success("ECC private key for signing generated successfully.")
                    except Exception as e:
                        st.error(f"Error generating ECC private key: {e}")

                st.text_area("Private Key (PEM Format)", st.session_state["ecc_sign_private_key"], height=150, key="ecc_sign_private_key_area")
                st.download_button(
                    label="Download Private Key",
                    data=st.session_state["ecc_sign_private_key"],
                    file_name="ecc_sign_private_key.pem",
                    mime="application/x-pem-file"
                )
                uploaded_file = st.file_uploader("Upload File to Sign (Text, Image, or Video)", type=["txt", "png", "jpg", "jpeg", "mp4"], key="ecc_sign_file")

                if st.button("Sign with ECC"):
                    try:
                        if not st.session_state["ecc_sign_private_key"]:
                            st.error("Please generate or provide a private key.")
                        elif not uploaded_file:
                            st.error("Please upload a file to sign.")
                        else:
                            file_content = uploaded_file.read()
                            signature = ecc_sign(file_content, st.session_state["ecc_sign_private_key"])
                            st.text_area("Digital Signature (ECC)", signature, height=100)
                            st.download_button(
                                label="Download Signature",
                                data=BytesIO(signature.encode()),
                                file_name="ecc_signature.txt",
                                mime="application/octet-stream"
                            )
                    except Exception as e:
                        st.error(f"Error signing with ECC: {e}")

            # Verification of Digital Signature Tab
            with tab_verify:
                st.subheader("Verification of Digital Signature")
                public_key_pem = st.text_area("Public Key (PEM Format)", key="verify_public_key")
                uploaded_file = st.file_uploader("Upload File to Verify (Text, Image, or Video)", type=["txt", "png", "jpg", "jpeg", "mp4"], key="verify_file")
                signature = st.text_area("Digital Signature", key="verify_signature")
                algorithm = st.selectbox("Algorithm", ["RSA", "ECC"], key="verify_algorithm")

                if st.button("Verify Signature"):
                    try:
                        if not public_key_pem or not uploaded_file or not signature:
                            st.error("Please provide the public key, upload a file, and provide the signature.")
                        else:
                            file_content = uploaded_file.read()
                            is_valid = verify_signature(file_content, signature, public_key_pem, algorithm)
                            if is_valid:
                                st.success("The signature is valid.")
                            else:
                                st.error("The signature is invalid.")
                    except Exception as e:
                        st.error(f"Error verifying signature: {e}")

    elif page == "Image and Video Encryption":
        st.header("Image and Video Encryption")
        st.subheader("Partial Image/Video Encryption (Demo)")
        tabs = st.tabs(["Image", "Video"])
        # --- IMAGE TAB ---
        with tabs[0]:
            algorithm = st.selectbox("Select Algorithm", ["AES"], key="imgenc_algorithm_partial")
            operation = st.selectbox("Operation", ["Encrypt", "Decrypt"], key="imgenc_operation_partial")
            uploaded_media = st.file_uploader("Upload an Image", type=["png", "jpg", "jpeg"], key="imgenc_file_partial")
            if "imgenc_key_temp" not in st.session_state:
                st.session_state["imgenc_key_temp"] = ""
            key = st.text_input("Key (16 bytes for AES)", value=st.session_state["imgenc_key_temp"], type="password", key="imgenc_key_partial")
            with st.expander("Generate Key from Password"):
                password = st.text_input("Enter Password for Key Generation", type="password", key="imgenc_password")
                if st.button("Generate Key for Image/Video Encryption", key="imgenc_btn_generate_key"):
                    if password:
                        try:
                            generated_key = get_key_from_password(password, truncate_to=16)
                            st.session_state["imgenc_key_temp"] = b64encode(generated_key).decode()
                            st.success("Key generated successfully.")
                        except Exception as e:
                            st.error(f"Error: {e}")
                    else:
                        st.error("Please enter a password to generate a key.")

            regions = []
            show_canvas = True
            if uploaded_media and uploaded_media.type.startswith("image/"):
                if operation == "Encrypt":
                    try:
                        from streamlit_drawable_canvas import st_canvas
                        st.info("Select regions to partially encrypt (pixelate) by drawing rectangles on the image below.")
                        if "imgenc_image_bytes" not in st.session_state or st.session_state.get("imgenc_image_name") != uploaded_media.name:
                            image_bytes = uploaded_media.read()
                            st.session_state["imgenc_image_bytes"] = image_bytes
                            st.session_state["imgenc_image_name"] = uploaded_media.name
                        else:
                            image_bytes = st.session_state["imgenc_image_bytes"]
                        image = Image.open(BytesIO(image_bytes))
                        st.image(image, caption="Original Image")
                        canvas_result = st_canvas(
                            fill_color="rgba(255, 0, 0, 0.3)",
                            stroke_width=2,
                            stroke_color="#FF0000",
                            background_image=image,
                            update_streamlit=True,
                            height=image.height,
                            width=image.width,
                            drawing_mode="rect",
                            key=f"canvas_{uploaded_media.name}",
                        )
                        if canvas_result.json_data is not None and "objects" in canvas_result.json_data:
                            for obj in canvas_result.json_data["objects"]:
                                if obj.get("type") == "rect":
                                    x = int(obj.get("left", 0))
                                    y = int(obj.get("top", 0))
                                    w = int(obj.get("width", 0))
                                    h = int(obj.get("height", 0))
                                    if w > 0 and h > 0:
                                        regions.append((x, y, w, h))
                    except Exception as e:
                        st.warning("Interactive region selection is unavailable or failed. Please enter regions manually below.")
                        st.error(f"Canvas error: {e}")
                        num_regions = st.number_input("Number of regions", min_value=1, max_value=10, value=1, step=1, key="num_regions_fallback")
                        for i in range(num_regions):
                            col1, col2, col3, col4 = st.columns(4)
                            with col1:
                                x = st.number_input(f"Region {i+1} - X", min_value=0, value=0, key=f"region_{i}_x_fallback")
                            with col2:
                                y = st.number_input(f"Region {i+1} - Y", min_value=0, value=0, key=f"region_{i}_y_fallback")
                            with col3:
                                w = st.number_input(f"Region {i+1} - Width", min_value=1, value=50, key=f"region_{i}_w_fallback")
                            with col4:
                                h = st.number_input(f"Region {i+1} - Height", min_value=1, value=50, key=f"region_{i}_h_fallback")
                            regions.append((int(x), int(y), int(w), int(h)))
                        uploaded_media.seek(0)
                        st.session_state["imgenc_image_bytes"] = uploaded_media.read()
                        st.session_state["imgenc_image_name"] = uploaded_media.name
                elif operation == "Decrypt":
                    show_canvas = False
                    if "imgenc_image_bytes" not in st.session_state or st.session_state.get("imgenc_image_name") != uploaded_media.name:
                        image_bytes = uploaded_media.read()
                        st.session_state["imgenc_image_bytes"] = image_bytes
                        st.session_state["imgenc_image_name"] = uploaded_media.name
                    st.markdown("**Provide the encrypted regions data (JSON) from the encryption step:**")
                    uploaded_json = st.file_uploader(
                        "Upload Encrypted Regions JSON file",
                        type=["json"],
                        key=f"imgenc_json_file_{uploaded_media.name}"
                    )
                    if uploaded_json is not None:
                        encrypted_regions_json = uploaded_json.read().decode()
                    else:
                        encrypted_regions_json = st.text_area(
                            "Or paste Encrypted Regions Data (JSON) here:",
                            value=st.session_state.get("imgenc_encrypted_regions", ""),
                            key=f"imgenc_encrypted_regions_input_{uploaded_media.name}"
                        )

            col_enc, col_dec = st.columns(2)
            encrypt_clicked = None
            decrypt_clicked = None
            if operation == "Encrypt":
                encrypt_clicked = col_enc.button("Encrypt Image", key="imgenc_btn_partial_encrypt")
            if operation == "Decrypt":
                decrypt_clicked = col_dec.button("Decrypt Image", key="imgenc_btn_partial_decrypt")

            if "imgenc_encrypted_regions" not in st.session_state:
                st.session_state["imgenc_encrypted_regions"] = ""

            if encrypt_clicked:
                try:
                    if uploaded_media is None:
                        st.error("Please upload an image or video.")
                    elif not key:
                        st.error("Please provide a key.")
                    elif not regions:
                        st.error("Please select or define at least one region on the image.")
                    else:
                        decoded_key = b64decode(key.encode()) if len(key) != 16 else key.encode()
                        if len(decoded_key) != 16:
                            st.error("Key must be exactly 16 bytes.")
                        else:
                            media_bytes = st.session_state.get("imgenc_image_bytes", None)
                            if media_bytes is None:
                                st.error("Image data not found. Please re-upload the image.")
                            elif algorithm == "AES":
                                protected_img, encrypted_regions_json = partial_encrypt_image(media_bytes, regions, key=decoded_key)
                                st.session_state["imgenc_encrypted_regions"] = encrypted_regions_json
                                st.success("Partial encryption applied to selected regions. Save the encrypted regions data for decryption.")
                                st.image(BytesIO(protected_img), caption="Partially Encrypted Image")
                                col_img, col_json = st.columns(2)
                                with col_img:
                                    st.download_button(
                                        label="Download Partially Encrypted Image",
                                        data=protected_img,
                                        file_name=f"partial_encrypted_{uploaded_media.name}",
                                        mime="image/png",
                                        key=f"download_img_{uploaded_media.name}"
                                    )
                                with col_json:
                                    st.download_button(
                                        label="Download Encrypted Regions Data (JSON)",
                                        data=encrypted_regions_json,
                                        file_name=f"encrypted_regions_{uploaded_media.name}.json",
                                        mime="application/json",
                                        key=f"download_json_{uploaded_media.name}"
                                    )
                except Exception as e:
                    st.error(f"Error: {e}")

            if decrypt_clicked:
                try:
                    if uploaded_media is None:
                        st.error("Please upload an image or video.")
                    elif not key:
                        st.error("Please provide a key.")
                    else:
                        decoded_key = b64decode(key.encode()) if len(key) != 16 else key.encode()
                        if len(decoded_key) != 16:
                            st.error("Key must be exactly 16 bytes.")
                        else:
                            media_bytes = st.session_state.get("imgenc_image_bytes", None)
                            if uploaded_media and uploaded_media.type.startswith("image/"):
                                if 'encrypted_regions_json' not in locals():
                                    encrypted_regions_json = st.session_state.get("imgenc_encrypted_regions", "")
                            else:
                                encrypted_regions_json = st.session_state.get("imgenc_encrypted_regions", "")
                            if not encrypted_regions_json:
                                st.error("Please provide the encrypted regions data (JSON) from the encryption step.")
                            elif media_bytes is None:
                                st.error("Image data not found. Please re-upload the image.")
                            elif algorithm == "AES":
                                try:
                                    decrypted_img = partial_decrypt_image(media_bytes, encrypted_regions_json, decoded_key)
                                    st.success("Image decrypted (regions restored) successfully.")
                                    st.download_button(
                                        label="Download Decrypted Image",
                                        data=decrypted_img,
                                        file_name=f"decrypted_{uploaded_media.name}",
                                        mime="image/png"
                                    )
                                except Exception as e:
                                    st.error(f"Decryption failed: {e}")
                except Exception as e:
                    st.error(f"Error: {e}")

        # --- VIDEO TAB ---
        with tabs[1]:
            from modes.im_vid import encrypt_video_faces, decrypt_video_faces
            st.subheader("AI-Based Selective Video Face Encryption/Decryption")
            video_algorithm = st.selectbox("Select Algorithm", ["AES"], key="video_algorithm")
            video_operation = st.selectbox("Operation", ["Encrypt", "Decrypt"], key="video_operation")
            uploaded_video = st.file_uploader("Upload a Video", type=["mp4"], key="imgenc_file_video")
            if "video_key_temp" not in st.session_state:
                st.session_state["video_key_temp"] = ""
            video_key = st.text_input("Key (16 bytes for AES)", value=st.session_state["video_key_temp"], type="password", key="video_key")
            # --- IV Generator moved directly under key field ---
            video_iv = st.text_input("IV (16 bytes, base64)", value="", type="password", key="video_iv")
            with st.expander("Generate IV (16 bytes, base64)"):
                if st.button("Generate IV", key="video_btn_generate_iv"):
                    import secrets, base64
                    iv = secrets.token_bytes(16)
                    st.session_state["video_iv_generated"] = b64encode(iv).decode()
                    st.success("IV generated successfully.")
                iv_val = st.session_state.get("video_iv_generated", "")
                st.text_input("Generated IV (copy to IV field above)", value=iv_val, key="video_iv_generated_display", disabled=True)
            # --- Key generator expander ---
            with st.expander("Generate Key for Video"):
                video_password = st.text_input("Enter Password for Key Generation", type="password", key="video_password")
                if st.button("Generate Key for Video", key="video_btn_generate_key"):
                    if video_password:
                        try:
                            generated_key = get_key_from_password(video_password, truncate_to=16)
                            st.session_state["video_key_temp"] = b64encode(generated_key).decode()
                            st.success("Key generated successfully.")
                        except Exception as e:
                            st.error(f"Error: {e}")
                    else:
                        st.error("Please enter a password to generate a key.")

            if video_operation == "Encrypt":
                # Always show both download buttons after encryption, using session state to store results
                if "video_encrypted_video_bytes" not in st.session_state:
                    st.session_state["video_encrypted_video_bytes"] = None
                if "video_metadata_json" not in st.session_state:
                    st.session_state["video_metadata_json"] = None

                encrypt_video_clicked = st.button("Encrypt Video", key="video_encrypt_btn")
                if encrypt_video_clicked:
                    if uploaded_video is None:
                        st.error("Please upload a video.")
                    elif not video_key or not video_iv:
                        st.error("Please provide both key and IV (16 bytes each, IV as base64).")
                    else:
                        try:
                            key_bytes = b64decode(video_key) if len(video_key) != 16 else video_key.encode()
                            iv_bytes = b64decode(video_iv) if len(video_iv) != 16 else video_iv.encode()
                            if len(key_bytes) != 16 or len(iv_bytes) != 16:
                                st.error("Key and IV must be exactly 16 bytes each.")
                            else:
                                video_bytes = uploaded_video.read()
                                encrypted_video_bytes, metadata_json = encrypt_video_faces(video_bytes, key_bytes, iv_bytes)
                                st.session_state["video_encrypted_video_bytes"] = encrypted_video_bytes
                                st.session_state["video_metadata_json"] = metadata_json
                                st.success("Video encrypted. Faces are blacked out. Download the encrypted video and metadata for decryption.")
                        except Exception as e:
                            st.error(f"Encryption failed: {e}")

                # Show download buttons if encryption has been performed
                if st.session_state.get("video_encrypted_video_bytes") and st.session_state.get("video_metadata_json"):
                    st.video(BytesIO(st.session_state["video_encrypted_video_bytes"]))
                    col_vid, col_json = st.columns(2)
                    with col_vid:
                        st.download_button(
                            label="Download Encrypted Video",
                            data=st.session_state["video_encrypted_video_bytes"],
                            file_name=f"encrypted_{uploaded_video.name if uploaded_video else 'video.mp4'}",
                            mime="video/mp4",
                            key=f"download_enc_video_{uploaded_video.name if uploaded_video else 'video'}"
                        )
                    with col_json:
                        st.download_button(
                            label="Download Encrypted Regions Data (JSON)",
                            data=st.session_state["video_metadata_json"],
                            file_name=f"encrypted_regions_{uploaded_video.name if uploaded_video else 'video'}.json",
                            mime="application/json",
                            key=f"download_enc_json_{uploaded_video.name if uploaded_video else 'video'}"
                        )

            if video_operation == "Decrypt":
                decrypt_video_clicked = st.button("Decrypt Video", key="video_decrypt_btn")
                video_metadata_json = None
                if uploaded_video is not None:
                    st.video(uploaded_video)
                uploaded_json = st.file_uploader(
                    "Upload Encrypted Regions JSON file",
                    type=["json"],
                    key=f"video_json_file_{uploaded_video.name if uploaded_video else 'none'}"
                )
                if uploaded_json is not None:
                    video_metadata_json = uploaded_json.read().decode()
                else:
                    video_metadata_json = st.text_area(
                        "Or paste Encrypted Regions Data (JSON) here:",
                        value="",
                        key=f"video_encrypted_regions_input_{uploaded_video.name if uploaded_video else 'none'}"
                    )
                if decrypt_video_clicked:
                    if uploaded_video is None:
                        st.error("Please upload a video.")
                    elif not video_key or not video_iv:
                        st.error("Please provide both key and IV (16 bytes each, IV as base64).")
                    elif not video_metadata_json:
                        st.error("Please provide the encrypted regions data (JSON) from the encryption step.")
                    else:
                        try:
                            key_bytes = b64decode(video_key) if len(video_key) != 16 else video_key.encode()
                            iv_bytes = b64decode(video_iv) if len(video_iv) != 16 else video_iv.encode()
                            if len(key_bytes) != 16 or len(iv_bytes) != 16:
                                st.error("Key and IV must be exactly 16 bytes each.")
                            else:
                                video_bytes = uploaded_video.read()
                                # For decryption, frame_shape is not used (kept for compatibility)
                                decrypted_video_bytes = decrypt_video_faces(
                                    video_bytes, key_bytes, iv_bytes, video_metadata_json, frame_shape=None
                                )
                                st.success("Video decrypted. Faces are restored.")
                                st.video(BytesIO(decrypted_video_bytes))
                                st.download_button(
                                    label="Download Decrypted Video",
                                    data=decrypted_video_bytes,
                                    file_name=f"decrypted_{uploaded_video.name}",
                                    mime="video/mp4",
                                    key=f"download_dec_video_{uploaded_video.name}"
                                )
                        except Exception as e:
                            st.error(f"Decryption failed: {e}")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        st.error(f"An unexpected error occurred: {e}")
