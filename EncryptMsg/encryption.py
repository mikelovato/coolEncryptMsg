import os
from cryptography.fernet import Fernet
from django.conf import settings
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

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

# Use a static salt for Fernet (can be changed if needed)
salt = bytes(b'0')

# Key generation for Fernet
settings.FERNET_KEY = base64.urlsafe_b64encode(generate_key(password, salt)).decode()  # Base64-encode for Fernet
fernet = Fernet(settings.FERNET_KEY)

def encrypt_message(method, message):
    if method == 'fernet':
        # Generate a random nonce
        nonce = os.urandom(16)  # 16 bytes nonce
        # Prepend nonce to the message
        message_with_nonce = nonce + message.encode()
        # Encrypt the message
        encrypted_message = fernet.encrypt(message_with_nonce)
        # Return the nonce and encrypted message
        return base64.urlsafe_b64encode(nonce).decode() + ':' + encrypted_message.decode()
    
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
        return (
            base64.urlsafe_b64encode(salt).decode() + ':' +
            base64.urlsafe_b64encode(iv).decode() + ':' +
            base64.urlsafe_b64encode(encrypted_message).decode()
        )
    
    else:
        raise ValueError("Unsupported encryption method")

def decrypt_message(method, encrypted_message):
    if method == 'fernet':
        # Split the nonce and encrypted message
        nonce_b64, encrypted_message_b64 = encrypted_message.split(':')
        nonce = base64.urlsafe_b64decode(nonce_b64)
        encrypted_message_bytes = encrypted_message_b64.encode()
        
        # Decrypt the message
        decrypted_message_with_nonce = fernet.decrypt(encrypted_message_bytes)
        
        # Return the decrypted message (removing the nonce)
        return decrypted_message_with_nonce[16:].decode()  # Remove the nonce
        
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
