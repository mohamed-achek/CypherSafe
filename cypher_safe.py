import streamlit as st
from algorithms import (
    aes_encrypt, aes_decrypt, generate_aes_key,
    des_encrypt, des_decrypt, generate_des_key,
    rsa_encrypt, rsa_decrypt, generate_rsa_keys,
    ecc_encrypt, ecc_decrypt, generate_ecc_keys,
    sha256_hash, sha512_hash, md5_hash,
    rsa_sign, ecc_sign, verify_signature
)
from base64 import b64encode
import os
from io import BytesIO

# Set the page configuration with a custom icon
st.set_page_config(page_title="CypherSafe", page_icon="Assets/white_on_trans.png")

def main():
    # Display the logo at the top of the app
    st.image("Assets/original.png", width=200)  # Adjust the width as needed
    st.title("CypherSafe")

    st.sidebar.title("Algorithms")
    st.sidebar.image("Assets/algo.png", width=200)  # Adjust the width as needed
    mode = st.sidebar.selectbox("Select Mode", ["Symmetric", "Asymmetric", "Hashing", "Digital Signature"])

    if mode == "Symmetric":
        st.header("Symmetric Encryption/Decryption")
        tab_aes, tab_fernet, tab_des = st.tabs(["AES", "Fernet", "DES"])

        # AES Tab
        with tab_aes:
            st.subheader("AES (Advanced Encryption Standard)")
            uploaded_file = st.file_uploader("Upload a File (Text, Image, or Video)", type=["txt", "png", "jpg", "jpeg", "mp4"])
            key = st.text_input("Key (16 bytes)", type="password")
            
            if st.button("Generate AES Key"):
                try:
                    generated_key = generate_aes_key(16)  # Ensure the generated key is exactly 16 bytes
                    st.text_area("Generated Key (16 bytes)", b64encode(generated_key).decode(), height=68)
                except ValueError as e:
                    st.error(f"Error: {e}")

            operation = st.selectbox("Operation", ["Encrypt", "Decrypt"], key="aes_operation")

            if st.button("Execute AES"):
                try:
                    if uploaded_file is None:
                        st.error("Please upload a file.")
                    elif len(key.encode()) != 16:
                        st.error(f"Invalid Key Length: Key must be exactly 16 bytes. Current length is {len(key.encode())} bytes.")
                    else:
                        file_content = uploaded_file.read()
                        if operation == "Encrypt":
                            result = aes_encrypt(file_content, key.encode())
                            file_name = f"encrypted_{uploaded_file.name}"
                        else:
                            result = aes_decrypt(file_content, key.encode())
                            file_name = f"decrypted_{uploaded_file.name}"
                        
                        st.text_area("Result", result, height=150)  # Adjusted height for better display
                        
                        # Provide download link for the result
                        st.download_button(
                            label="Download Result",
                            data=BytesIO(result.encode() if isinstance(result, str) else result),
                            file_name=file_name,
                            mime="application/octet-stream"
                        )
                except Exception as e:
                    st.error(f"Error: {e}")

        # Fernet Tab
        with tab_fernet:
            st.subheader("Fernet (Symmetric Encryption Using AES)")
            uploaded_file = st.file_uploader("Upload a File (Text, Image, or Video)", type=["txt", "png", "jpg", "jpeg", "mp4"], key="fernet_file")
            key = st.text_input("Key", type="password", key="fernet_key")
            
            if st.button("Generate Fernet Key"):
                fernet_key = Fernet.generate_key()
                st.text_area("Generated Key", fernet_key.decode(), height=68)  # Adjusted height

            operation = st.selectbox("Operation", ["Encrypt", "Decrypt"], key="fernet_operation")

            if st.button("Execute Fernet"):
                try:
                    if uploaded_file is None:
                        st.error("Please upload a file.")
                    else:
                        file_content = uploaded_file.read()
                        fernet = Fernet(key.encode())
                        if operation == "Encrypt":
                            result = fernet.encrypt(file_content).decode()
                            file_name = f"encrypted_{uploaded_file.name}"
                        else:
                            result = fernet.decrypt(file_content).decode()
                            file_name = f"decrypted_{uploaded_file.name}"
                        
                        st.text_area("Result", result, height=150)  # Adjusted height
                        
                        # Provide download link for the result
                        st.download_button(
                            label="Download Result",
                            data=BytesIO(result.encode() if isinstance(result, str) else result),
                            file_name=file_name,
                            mime="application/octet-stream"
                        )
                except Exception as e:
                    st.error(f"Error: {e}")

        # DES Tab
        with tab_des:
            st.subheader("DES (Data Encryption Standard)")
            uploaded_file = st.file_uploader("Upload a File (Text, Image, or Video)", type=["txt", "png", "jpg", "jpeg", "mp4"], key="des_file")
            key = st.text_input("Key (8 bytes)", type="password", key="des_key")
            
            if st.button("Generate DES Key"):
                generated_key = generate_des_key()
                st.text_area("Generated Key", b64encode(generated_key).decode(), height=68)  # Adjusted height

            operation = st.selectbox("Operation", ["Encrypt", "Decrypt"], key="des_operation")

            if st.button("Execute DES"):
                try:
                    if uploaded_file is None:
                        st.error("Please upload a file.")
                    elif len(key.encode()) != 8:
                        st.error("Key must be 8 bytes for DES.")
                    else:
                        file_content = uploaded_file.read()
                        if operation == "Encrypt":
                            result = des_encrypt(file_content, key.encode())
                            file_name = f"encrypted_{uploaded_file.name}"
                        else:
                            result = des_decrypt(file_content, key.encode())
                            file_name = f"decrypted_{uploaded_file.name}"
                        
                        st.text_area("Result", result, height=150)  # Adjusted height
                        
                        # Provide download link for the result
                        st.download_button(
                            label="Download Result",
                            data=BytesIO(result.encode() if isinstance(result, str) else result),
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
                if st.button("Generate RSA Keys"):
                    private_key, public_key = generate_rsa_keys()
                    st.text_area("Private Key", private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    ).decode(), height=150)
                    st.text_area("Public Key", public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ).decode(), height=150)

            elif operation == "Encrypt":
                plaintext = st.text_area("Input Text", key="rsa_plaintext")
                public_key_pem = st.text_area("Public Key", key="rsa_public_key")
                if st.button("Encrypt RSA"):
                    try:
                        public_key = serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
                        result = rsa_encrypt(plaintext, public_key)
                        st.text_area("Result", result, height=100)
                        
                        # Provide download link for the result
                        st.download_button(
                            label="Download Result",
                            data=BytesIO(result.encode() if isinstance(result, str) else result),
                            file_name="encrypted_rsa.txt",
                            mime="application/octet-stream"
                        )
                    except Exception as e:
                        st.error(f"Error: {e}")

            elif operation == "Decrypt":
                ciphertext = st.text_area("Ciphertext", key="rsa_ciphertext")
                private_key_pem = st.text_area("Private Key", key="rsa_private_key")
                if st.button("Decrypt RSA"):
                    try:
                        private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None, backend=default_backend())
                        result = rsa_decrypt(ciphertext, private_key)
                        st.text_area("Result", result, height=100)
                        
                        # Provide download link for the result
                        st.download_button(
                            label="Download Result",
                            data=BytesIO(result.encode() if isinstance(result, str) else result),
                            file_name="decrypted_rsa.txt",
                            mime="application/octet-stream"
                        )
                    except Exception as e:
                        st.error(f"Error: {e}")

        # ECC Tab
        with tab_ecc:
            st.subheader("ECC (Elliptic Curve Cryptography)")
            operation = st.selectbox("Operation", ["Generate Keys", "Encrypt", "Decrypt"], key="ecc_operation")

            if operation == "Generate Keys":
                if st.button("Generate ECC Keys"):
                    private_key, public_key = generate_ecc_keys()
                    st.text_area("Private Key", private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    ).decode(), height=150)
                    st.text_area("Public Key", public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ).decode(), height=150)

            elif operation == "Encrypt":
                plaintext = st.text_area("Input Text", key="ecc_plaintext")
                public_key_pem = st.text_area("Public Key", key="ecc_public_key")
                if st.button("Encrypt ECC"):
                    try:
                        # Placeholder for ECC encryption
                        result = ecc_encrypt(plaintext, public_key_pem)
                        st.text_area("Result", result, height=100)
                        
                        # Provide download link for the result
                        st.download_button(
                            label="Download Result",
                            data=BytesIO(result.encode() if isinstance(result, str) else result),
                            file_name="encrypted_ecc.txt",
                            mime="application/octet-stream"
                        )
                    except Exception as e:
                        st.error(f"Error: {e}")

            elif operation == "Decrypt":
                ciphertext = st.text_area("Ciphertext", key="ecc_ciphertext")
                private_key_pem = st.text_area("Private Key", key="ecc_private_key")
                if st.button("Decrypt ECC"):
                    try:
                        # Placeholder for ECC decryption
                        result = ecc_decrypt(ciphertext, private_key_pem)
                        st.text_area("Result", result, height=100)
                        
                        # Provide download link for the result
                        st.download_button(
                            label="Download Result",
                            data=BytesIO(result.encode() if isinstance(result, str) else result),
                            file_name="decrypted_ecc.txt",
                            mime="application/octet-stream"
                        )
                    except Exception as e:
                        st.error(f"Error: {e}")

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
            private_key_pem = st.text_area("Private Key (PEM Format)", key="rsa_sign_private_key")
            message = st.text_area("Message to Sign", key="rsa_sign_message")
            if st.button("Sign with RSA"):
                try:
                    if not private_key_pem or not message:
                        st.error("Please provide both the private key and the message.")
                    else:
                        signature = rsa_sign(message, private_key_pem)
                        st.text_area("Digital Signature (RSA)", signature, height=100)
                        
                        # Provide download link for the result
                        st.download_button(
                            label="Download Result",
                            data=BytesIO(signature.encode() if isinstance(signature, str) else signature),
                            file_name="rsa_signature.txt",
                            mime="application/octet-stream"
                        )
                except Exception as e:
                    st.error(f"Error: {e}")

        # ECC Digital Signature Tab
        with tab_ecc_sign:
            st.subheader("ECC Digital Signature")
            private_key_pem = st.text_area("Private Key (PEM Format)", key="ecc_sign_private_key")
            message = st.text_area("Message to Sign", key="ecc_sign_message")
            if st.button("Sign with ECC"):
                try:
                    if not private_key_pem or not message:
                        st.error("Please provide both the private key and the message.")
                    else:
                        signature = ecc_sign(message, private_key_pem)
                        st.text_area("Digital Signature (ECC)", signature, height=100)
                        
                        # Provide download link for the result
                        st.download_button(
                            label="Download Result",
                            data=BytesIO(signature.encode() if isinstance(signature, str) else signature),
                            file_name="ecc_signature.txt",
                            mime="application/octet-stream"
                        )
                except Exception as e:
                    st.error(f"Error: {e}")

        # Verification of Digital Signature Tab
        with tab_verify:
            st.subheader("Verification of Digital Signature")
            public_key_pem = st.text_area("Public Key (PEM Format)", key="verify_public_key")
            message = st.text_area("Message", key="verify_message")
            signature = st.text_area("Digital Signature", key="verify_signature")
            algorithm = st.selectbox("Algorithm", ["RSA", "ECC"], key="verify_algorithm")
            if st.button("Verify Signature"):
                try:
                    if not public_key_pem or not message or not signature:
                        st.error("Please provide the public key, message, and signature.")
                    else:
                        is_valid = verify_signature(message, signature, public_key_pem, algorithm)
                        if is_valid:
                            st.success("The signature is valid.")
                        else:
                            st.error("The signature is invalid.")
                except Exception as e:
                    st.error(f"Error: {e}")

if __name__ == "__main__":
    main()
