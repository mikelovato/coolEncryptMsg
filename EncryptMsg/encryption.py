import os
import base64
from cryptography.fernet import Fernet
from django.conf import settings
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

# Define the password that will be used for key derivation
password = b"passwordexample"

# Function to generate a key using PBKDF2HMAC
def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes for AES-256
        salt=salt,
        iterations=480000,
    )
    return kdf.derive(password)  # Return raw key bytes for AES

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def serialize_private_key(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

def rsa_encrypt(public_key, message):
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def rsa_decrypt(private_key, encrypted_message):
    plaintext = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()

def encrypt_message(method, message):
    if method == 'fernet':
        # Fernet encryption code...
        # (existing code unchanged)
    
    elif method == 'aes_cfb':
        # AES encryption code...
        # (existing code unchanged)

    elif method == 'chacha20_poly1305':
        # ChaCha20-Poly1305 encryption code...
        # (existing code unchanged)

    elif method == 'rsa':
        private_key, public_key = generate_rsa_keys()  # Generate RSA keys
        encrypted_message = rsa_encrypt(public_key, message)
        return (
            base64.urlsafe_b64encode(serialize_private_key(private_key)).decode() + ':' +
            base64.urlsafe_b64encode(encrypted_message).decode()
        )
    
    else:
        raise ValueError("Unsupported encryption method")

def decrypt_message(method, encrypted_message):
    if method == 'fernet':
        # Fernet decryption code...
        # (existing code unchanged)
    
    elif method == 'aes_cfb':
        # AES decryption code...
        # (existing code unchanged)

    elif method == 'chacha20_poly1305':
        # ChaCha20-Poly1305 decryption code...
        # (existing code unchanged)

    elif method == 'rsa':
        private_key_b64, encrypted_message_b64 = encrypted_message.split(':')
        private_key = serialization.load_pem_private_key(
            base64.urlsafe_b64decode(private_key_b64),
            password=None,
        )
        encrypted_message = base64.urlsafe_b64decode(encrypted_message_b64)
        return rsa_decrypt(private_key, encrypted_message)

    else:
        return 'Unsupported encryption method'
