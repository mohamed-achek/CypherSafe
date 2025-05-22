import streamlit as st
import face_recognition
import numpy as np
import cv2
from PIL import Image

st.title("Face Recognition Login")

# Load known face encoding from file
def load_known_face_encoding(image_path):
    try:
        known_image = face_recognition.load_image_file(image_path)
        known_encodings = face_recognition.face_encodings(known_image)
        if not known_encodings:
            st.error("No face found in the known user image.")
            return None
        return known_encodings[0]
    except Exception as e:
        st.error(f"Error loading known face: {e}")
        return None

# Compare faces
def compare_faces(known_encoding, unknown_encoding, tolerance=0.6):
    results = face_recognition.compare_faces([known_encoding], unknown_encoding, tolerance)
    return results[0]

# Main app logic
def main():
    import os
    st.sidebar.title("Navigation")
    page = st.sidebar.radio("Go to", ["Face Login", "App"], key="main_nav")

    if page == "Face Login":
        # Face login page only
        if "login_state" not in st.session_state:
            st.session_state["login_state"] = False
        user_dir = "users"
        user_files = [f for f in os.listdir(user_dir) if f.endswith(".jpg")]
        st.write("Please use your camera to login with your face.")
        camera_image = st.camera_input("Take a picture to login")
        if camera_image is not None:
            img = Image.open(camera_image)
            img_array = np.array(img)
            img_bgr = cv2.cvtColor(img_array, cv2.COLOR_RGB2BGR)
            unknown_encodings = face_recognition.face_encodings(img_bgr)
            if not unknown_encodings:
                st.error("No face detected in the captured image. Please try again.")
                st.session_state["login_state"] = False
                st.stop()
            unknown_encoding = unknown_encodings[0]
            match_found = False
            matched_user = None
            for user_file in user_files:
                known_path = os.path.join(user_dir, user_file)
                known_encoding = load_known_face_encoding(known_path)
                if known_encoding is not None:
                    if compare_faces(known_encoding, unknown_encoding):
                        match_found = True
                        matched_user = os.path.splitext(user_file)[0]
                        break
            if match_found:
                st.success(f"Face recognized! Welcome, {matched_user}. Login successful.")
                st.session_state["login_state"] = True
                st.session_state["current_user"] = matched_user
            else:
                st.error("Face not recognized. Access denied.")
                st.session_state["login_state"] = False
        if st.session_state["login_state"]:
            st.info(f"You are logged in as {st.session_state.get('current_user', '')}!")
        else:
            st.info("Not logged in.")
    elif page == "App":
        # All other app logic goes here, but only if logged in
        if not st.session_state.get("login_state", False):
            st.warning("Please login with your face first on the 'Face Login' page.")
            st.stop()
        st.success(f"Welcome, {st.session_state.get('current_user', '')}! You are logged in.")
        # ... Place your main app code here ...
        st.write("App content goes here.")

if __name__ == "__main__":
    main()
