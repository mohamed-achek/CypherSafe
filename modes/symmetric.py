import streamlit as st
from algorithms import aes_encrypt, aes_decrypt, des_encrypt, des_decrypt
from base64 import b64encode, b64decode
from database import get_key_from_password

def symmetric_mode():
    st.header("Symmetric Encryption/Decryption")
    tab_aes, tab_fernet, tab_des = st.tabs(["AES", "Fernet", "DES"])

    # AES Tab
    with tab_aes:
        st.subheader("AES (Advanced Encryption Standard)")
        uploaded_file = st.file_uploader("Upload a File", type=["txt", "png", "jpg", "jpeg", "mp4"])
        if "aes_key_temp" not in st.session_state:
            st.session_state["aes_key_temp"] = ""
        key = st.text_input("Key (16 bytes)", value=st.session_state["aes_key_temp"], type="password", key="aes_key")
        if st.button("Generate AES Key"):
            password = st.text_input("Enter Password for Key Generation", type="password", key="aes_password")
            if password:
                try:
                    generated_key = get_key_from_password(password)
                    st.session_state["aes_key_temp"] = b64encode(generated_key).decode()
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
                    decoded_key = b64decode(key.encode())
                    file_content = uploaded_file.read()
                    if operation == "Encrypt":
                        result = aes_encrypt(file_content, decoded_key)
                        file_name = f"encrypted_{uploaded_file.name}"
                    else:
                        result = aes_decrypt(file_content, decoded_key)
                        file_name = f"decrypted_{uploaded_file.name}"
                    st.download_button("Download Result", data=result, file_name=file_name, mime="application/octet-stream")
            except Exception as e:
                st.error(f"Error: {e}")

    # Fernet Tab
    with tab_fernet:
        # Similar logic as AES, but using Fernet encryption
        pass

    # DES Tab
    with tab_des:
        # Similar logic as AES, but using DES encryption
        pass
