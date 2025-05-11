import streamlit as st
from algorithms import rsa_sign, ecc_sign, verify_signature

def digital_signature_mode():
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
                    signature = rsa_sign(message.encode(), private_key_pem)
                    st.text_area("Digital Signature (RSA)", signature, height=100)
            except Exception as e:
                st.error(f"Error: {e}")

    # ECC Digital Signature Tab
    with tab_ecc_sign:
        # Similar logic as RSA, but using ECC
        pass

    # Verification Tab
    with tab_verify:
        # Logic for verifying digital signatures
        pass
