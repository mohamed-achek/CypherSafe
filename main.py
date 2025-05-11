import streamlit as st
from ui import display_logo, display_sidebar
from modes.symmetric import symmetric_mode
from modes.asymmetric import asymmetric_mode
from modes.hashing import hashing_mode
from modes.digital_signature import digital_signature_mode
from password_system import main as password_system_main
from database import init_db

def main():
    # Initialize the database
    init_db()

    # Display the logo and sidebar
    display_logo()
    mode = display_sidebar()

    # Handle different modes
    if mode == "Password System":
        try:
            password_system_main()
        except Exception as e:
            st.error(f"Error in Password System: {e}")
    elif mode == "Symmetric":
        symmetric_mode()
    elif mode == "Asymmetric":
        asymmetric_mode()
    elif mode == "Hashing":
        hashing_mode()
    elif mode == "Digital Signature":
        digital_signature_mode()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        st.error(f"An unexpected error occurred: {e}")
