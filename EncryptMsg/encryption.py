import os
from cryptography.fernet import Fernet
from django.conf import settings
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Define the password that will be used for key derivation
password = b"passwordexample"

# Function to generate a key using PBKDF2HMAC
def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password))

# Use a static salt for Fernet (can be changed if needed)
salt = bytes(b'0')

# Key generation for Fernet
settings.FERNET_KEY = generate_key(password, salt)
fernet = Fernet(settings.FERNET_KEY)

def encrypt_message(method, message):
    if method == 'fernet':
        return fernet.encrypt(message.encode()).decode()
    
    elif method == 'aes_cfb':
        # AES encryption using CFB mode
        salt = os.urandom(16)  # Generate a random salt for each encryption
        key = generate_key(password, salt)  # Generate a key using the random salt
        iv = os.urandom(16)  # Initialization vector for AES
        
        # Encrypt the message using AES in CFB mode
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()
        
        # Return salt, IV, and encrypted message (concatenated with ':')
        return base64.urlsafe_b64encode(salt).decode() + ':' + base64.urlsafe_b64encode(iv).decode() + ':' + base64.urlsafe_b64encode(encrypted_message).decode()
    
    else:
        raise ValueError("Unsupported encryption method")

def decrypt_message(method, encrypted_message):
    if method == 'fernet':
        return fernet.decrypt(encrypted_message.encode()).decode()
    
    elif method == 'aes_cfb':
        # Split the salt, IV, and ciphertext from the encrypted message
        salt_b64, iv_b64, ciphertext_b64 = encrypted_message.split(':')
        salt = base64.urlsafe_b64decode(salt_b64)
        iv = base64.urlsafe_b64decode(iv_b64)
        ciphertext = base64.urlsafe_b64decode(ciphertext_b64)
        
        # Generate the key using the same salt
        key = generate_key(password, salt)
        
        # Decrypt the message using AES in CFB mode
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode()
    
    else:
        return 'Unsupported encryption method'
