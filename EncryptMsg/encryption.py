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

# Generate RSA keys once at the start
private_key, public_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
), None  # Set this later

# Function to generate a key using PBKDF2HMAC
def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes for AES-256
        salt=salt,
        iterations=480000,
    )
    return kdf.derive(password)  # Return raw key bytes for AES

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

def fernet_encrypt(message):
    key = Fernet.generate_key()
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message.encode())
    return base64.urlsafe_b64encode(key).decode() + ':' + encrypted_message.decode()

def fernet_decrypt(encrypted_message):
    key_b64, encrypted_message_b64 = encrypted_message.split(':')
    key = base64.urlsafe_b64decode(key_b64)
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_message_b64.encode()).decode()

def aes_encrypt(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return base64.urlsafe_b64encode(iv).decode() + ':' + base64.urlsafe_b64encode(ciphertext).decode()

def aes_decrypt(encrypted_message, key):
    iv_b64, ciphertext_b64 = encrypted_message.split(':')
    iv = base64.urlsafe_b64decode(iv_b64)
    ciphertext = base64.urlsafe_b64decode(ciphertext_b64)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return (decryptor.update(ciphertext) + decryptor.finalize()).decode()

def chacha20_encrypt(message, key):
    cipher = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    ciphertext = cipher.encrypt(nonce, message.encode(), None)
    return base64.urlsafe_b64encode(nonce).decode() + ':' + base64.urlsafe_b64encode(ciphertext).decode()

def chacha20_decrypt(encrypted_message, key):
    nonce_b64, ciphertext_b64 = encrypted_message.split(':')
    nonce = base64.urlsafe_b64decode(nonce_b64)
    ciphertext = base64.urlsafe_b64decode(ciphertext_b64)
    cipher = ChaCha20Poly1305(key)
    return cipher.decrypt(nonce, ciphertext, None).decode()

def encrypt_message(method, message):
    if method == 'fernet':
        return fernet_encrypt(message)
    
    elif method == 'aes_cfb':
        salt = os.urandom(16)
        key = generate_key(password, salt)  # Generate key using PBKDF2HMAC
        return aes_encrypt(message, key)

    elif method == 'chacha20_poly1305':
        key = os.urandom(32)  # Generate a new key for ChaCha20
        return chacha20_encrypt(message, key)

    elif method == 'rsa':
        global public_key  # Use the global public_key variable
        if public_key is None:
            public_key = private_key.public_key()  # Get the public key from the private key
        encrypted_message = rsa_encrypt(public_key, message)
        return (
            base64.urlsafe_b64encode(serialize_private_key(private_key)).decode() + ':' +
            base64.urlsafe_b64encode(encrypted_message).decode()
        )
    
    else:
        raise ValueError("Unsupported encryption method")

def decrypt_message(method, encrypted_message):
    if method == 'fernet':
        return fernet_decrypt(encrypted_message)
    
    elif method == 'aes_cfb':
        salt = os.urandom(16)  # Re-generate the salt (store this securely in practice)
        key = generate_key(password, salt)
        return aes_decrypt(encrypted_message, key)

    elif method == 'chacha20_poly1305':
        key = os.urandom(32)  # In practice, you need to securely store and retrieve this key
        return chacha20_decrypt(encrypted_message, key)

    elif method == 'rsa':
        private_key_b64, encrypted_message_b64 = encrypted_message.split(':')
        private_key = serialization.load_pem_private_key(
            base64.urlsafe_b64decode(private_key_b64),
            password=None,
        )
        encrypted_message = base64.urlsafe_b64decode(encrypted_message_b64)
        return rsa_decrypt(private_key, encrypted_message)

    else:
        raise ValueError("Unsupported encryption method")
