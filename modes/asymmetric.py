import streamlit as st
from algorithms import rsa_encrypt, rsa_decrypt, generate_rsa_keys, ecc_encrypt, ecc_decrypt, generate_ecc_keys

def asymmetric_mode():
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

    # ECC Tab
    with tab_ecc:
        # Similar logic as RSA, but using ECC encryption
        pass
