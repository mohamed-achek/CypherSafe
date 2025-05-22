import streamlit as st

def display_logo():
    """Display the application logo."""
    try:
        st.image("Assets/original.png", width=200)
    except FileNotFoundError:
        st.warning("Logo not found. Ensure 'Assets/original.png' exists.")
    st.title("CypherSafe")

def display_sidebar():
    """Display the sidebar with mode selection."""
    st.sidebar.title("Algorithms")
    try:
        st.sidebar.image("Assets/algorithms.png", width=200)
    except FileNotFoundError:
        st.warning("Sidebar image not found. Ensure 'Assets/algorithms.png' exists.")
    return st.sidebar.selectbox("Select Mode", ["Symmetric", "Asymmetric", "Hashing", "Digital Signature", "Password System"])
