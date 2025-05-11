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
    row = cursor.fetchone()
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

    st.sidebar.title("Algorithms")
    try:
        st.sidebar.image("Assets/algo.png", width=200)  # Adjust the width as needed
    except FileNotFoundError:
        st.warning("Sidebar image not found. Ensure 'Assets/algo.png' exists.")
    mode = st.sidebar.selectbox("Select Mode", ["Symmetric", "Asymmetric", "Hashing", "Digital Signature"])

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

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        st.error(f"An unexpected error occurred: {e}")
