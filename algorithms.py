from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec, utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from base64 import b64encode, b64decode
import secrets
from cryptography.fernet import Fernet
from Crypto.Cipher import DES

# Helper function to handle binary data
def encode_binary(data):
    return b64encode(data).decode()

def decode_binary(data):
    return b64decode(data)

# Symmetric Encryption/Decryption (AES)
def aes_encrypt(data, key):
    if len(key) not in [16, 24, 32]:
        raise ValueError("AES key must be 16, 24, or 32 bytes")
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return encode_binary(iv + ciphertext)

def aes_decrypt(data, key):
    if len(key) not in [16, 24, 32]:
        raise ValueError("AES key must be 16, 24, or 32 bytes")
    decoded_data = decode_binary(data)
    iv, ciphertext = decoded_data[:16], decoded_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def generate_aes_key(key_size=16):
    if key_size != 16:  # Ensure the key size is exactly 16 bytes for AES
        raise ValueError("AES key size must be exactly 16 bytes.")
    key = secrets.token_bytes(key_size)
    if len(key) != 16:  # Double-check the generated key length
        raise ValueError(f"Generated AES key is {len(key)} bytes long, expected 16 bytes.")
    return key

# Key Generator for DES
def generate_des_key():
    return secrets.token_bytes(8)  # DES requires an 8-byte key

# DES Encryption/Decryption
def des_encrypt(data, key):
    cipher = DES.new(key, DES.MODE_ECB)
    padded_data = data + (8 - len(data) % 8) * b" "  # Pad to multiple of 8 bytes
    ciphertext = cipher.encrypt(padded_data)
    return encode_binary(ciphertext)

def des_decrypt(data, key):
    decoded_data = decode_binary(data)
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted_data = cipher.decrypt(decoded_data)
    return decrypted_data.rstrip(b" ")  # Remove padding

# RSA Encryption/Decryption
def rsa_encrypt(data, public_key_pem):
    """Encrypt data using RSA public key."""
    public_key = serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
    ciphertext = public_key.encrypt(
        data.encode(),  # Ensure data is encoded to bytes
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encode_binary(ciphertext)

def rsa_decrypt(data, private_key_pem):
    """Decrypt data using RSA private key."""
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None, backend=default_backend())
    decoded_data = decode_binary(data)
    plaintext = private_key.decrypt(
        decoded_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()  # Decode bytes to string

def generate_rsa_keys():
    """Generate RSA private and public keys."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()  # Convert bytes to string
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()  # Convert bytes to string
    return private_key_pem, public_key_pem

# ECC Encryption/Decryption (Placeholder for demonstration)
def ecc_encrypt(data, public_key_pem):
    """Encrypt data using ECC public key (Placeholder)."""
    # ECC encryption is not natively supported in Python.
    # This is a placeholder to demonstrate functionality.
    return f"Encrypted (ECC): {data}"

def ecc_decrypt(data, private_key_pem):
    """Decrypt data using ECC private key (Placeholder)."""
    # ECC decryption is not natively supported in Python.
    # This is a placeholder to demonstrate functionality.
    return f"Decrypted (ECC): {data}"

def generate_ecc_keys():
    """Generate ECC private and public keys."""
    private_key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
    public_key = private_key.public_key()
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()  # Convert bytes to string
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()  # Convert bytes to string
    return private_key_pem, public_key_pem

# Hashing (SHA-256)
def sha256_hash(data):
    if isinstance(data, str):
        data = data.encode()  # Convert string to bytes
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    return digest.finalize().hex()

# Hashing (SHA-512)
def sha512_hash(data):
    if isinstance(data, str):
        data = data.encode()  # Convert string to bytes
    digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
    digest.update(data)
    return digest.finalize().hex()

# Hashing (MD5)
def md5_hash(data):
    if isinstance(data, str):
        data = data.encode()  # Convert string to bytes
    digest = hashes.Hash(hashes.MD5(), backend=default_backend())
    digest.update(data)
    return digest.finalize().hex()

# RSA Digital Signature
def rsa_sign(data, private_key_pem):
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None, backend=default_backend())
    signature = private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return encode_binary(signature)

# ECC Digital Signature
def ecc_sign(data, private_key_pem):
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None, backend=default_backend())
    signature = private_key.sign(
        data,
        ec.ECDSA(hashes.SHA256())
    )
    return encode_binary(signature)

# Verification of Digital Signature
def verify_signature(data, signature, public_key_pem, algorithm):
    public_key = serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
    signature_bytes = decode_binary(signature)
    try:
        if algorithm == "RSA":
            public_key.verify(
                signature_bytes,
                data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
        elif algorithm == "ECC":
            public_key.verify(
                signature_bytes,
                data,
                ec.ECDSA(hashes.SHA256())
            )
        return True
    except Exception:
        return False
