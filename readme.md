# CypherSafe: File, Image, and Video Encryption, Decryption & Hashing Tool

Welcome to **CypherSafe** — a modern Python-based application for securing your files, images, and videos using advanced cryptography and AI-based face detection.

---

## 🚀 Features

- **🔒 File Encryption/Decryption**
  - Symmetric: AES, Fernet, DES
  - Asymmetric: RSA, ECC (ECC is a placeholder for demo)
- **🖼️ Partial Image Encryption**
  - Select regions on images to encrypt (with pixelation preview)
- **🎥 AI-Based Video Face Encryption**
  - Detects faces in videos using [MediaPipe](https://google.github.io/mediapipe/) and encrypts only face regions
  - Download encrypted video and metadata for decryption
- **🔑 Secure Key & IV Generation**
  - Password-based key derivation and secure random IV generator (base64)
- **🔎 Hashing**
  - SHA-256, SHA-512, MD5
- **✍️ Digital Signatures**
  - RSA and ECC (sign/verify)
- **📂 Download Results**
  - Save encrypted/decrypted files, images, videos, and JSON metadata

---

## 🛡️ Security Notes

- Keys are generated per session and can be derived from passwords.
- IVs are generated securely and must be saved for decryption.
- Encrypted regions metadata (JSON) is required to restore images/videos.
- Uses [cryptography](https://cryptography.io/) and [mediapipe](https://google.github.io/mediapipe/) for robust security and AI face detection.

---

## 🖥️ User Interface

- Built with [Streamlit](https://streamlit.io/) for an intuitive, interactive web UI.
- Draw rectangles on images to select regions for partial encryption.
- Upload videos and encrypt/decrypt faces with a single click.

---

## 🧰 Requirements

- Python 3.8+
- See `requirements.txt` for dependencies:
  - cryptography
  - pycryptodome
  - streamlit
  - opencv-python-headless
  - numpy
  - pillow
  - streamlit-drawable-canvas
  - mediapipe

---

## 🧟️ Future Improvements

- 🎨 Advanced region selection for videos (beyond faces)
- ⚙️ Batch processing and folder encryption
- 📬 Secure key sharing options
- 📈 Progress bars for large files/videos

---

## 🤝 Contributing

Pull requests are welcome! Open an issue to discuss changes or improvements.

---

## ⚠️ Disclaimer

- Keep your keys and IVs safe! Losing them means losing access to your encrypted data.
- ECC encryption is a placeholder and not secure for real use.
- For production, always review and test cryptographic implementations thoroughly.
