import streamlit as st
from algorithms import sha256_hash, sha512_hash, md5_hash

def hashing_mode():
    st.header("Hashing")
    tab_sha256, tab_sha512, tab_md5 = st.tabs(["SHA-256", "SHA-512", "MD5"])

    # SHA-256 Tab
    with tab_sha256:
        st.subheader("SHA-256")
        uploaded_file = st.file_uploader("Upload a File", type=["txt", "png", "jpg", "jpeg", "mp4"], key="sha256_file")
        if st.button("Hash with SHA-256"):
            try:
                if uploaded_file is None:
                    st.error("Please upload a file.")
                else:
                    file_content = uploaded_file.read()
                    result = sha256_hash(file_content)
                    st.text_area("Hash Value (SHA-256)", result, height=100)
            except Exception as e:
                st.error(f"Error: {e}")

    # SHA-512 Tab
    with tab_sha512:
        # Similar logic as SHA-256, but using SHA-512
        pass

    # MD5 Tab
    with tab_md5:
        # Similar logic as SHA-256, but using MD5
        pass
