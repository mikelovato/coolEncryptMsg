import os
import base64
import bcrypt
import time  # Import the time module to track the time taken
from django.conf import settings
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend

password = b"passwordexample"

# Function to generate a key using PBKDF2HMAC
def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes for AES-256
        salt=salt,
        iterations=480000,
    )
    return kdf.derive(password)

def encrypt_message(method, message):
    start_time = time.time()  # Record the start time

    if method == 'fernet':
        salt = os.urandom(16)
        key = base64.urlsafe_b64encode(generate_key(password, salt)).decode()
        fernet = Fernet(key)
        nonce = os.urandom(16)
        message_with_nonce = nonce + message.encode()
        encrypted_message = fernet.encrypt(message_with_nonce)
        encrypted_result = (
            base64.urlsafe_b64encode(nonce).decode() + ':' +
            base64.urlsafe_b64encode(salt).decode() + ':' +
            encrypted_message.decode()
        )
    
    elif method == 'aes_cfb':
        salt = os.urandom(16)
        key = generate_key(password, salt)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()
        encrypted_result = (
            base64.urlsafe_b64encode(salt).decode() + ':' +
            base64.urlsafe_b64encode(iv).decode() + ':' +
            base64.urlsafe_b64encode(encrypted_message).decode()
        )
    
    elif method == 'chacha20_poly1305':
        key = os.urandom(32)
        nonce = os.urandom(12)
        cipher = ChaCha20Poly1305(key)
        encrypted_message = cipher.encrypt(nonce, message.encode(), None)
        encrypted_result = (
            base64.urlsafe_b64encode(nonce).decode() + ':' +
            base64.urlsafe_b64encode(key).decode() + ':' +
            base64.urlsafe_b64encode(encrypted_message).decode()
        )
    
    elif method == 'aes_ctr':
        salt = os.urandom(16)
        key = generate_key(password, salt)
        nonce = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()
        encrypted_result = (
            base64.urlsafe_b64encode(salt).decode() + ':' +
            base64.urlsafe_b64encode(nonce).decode() + ':' +
            base64.urlsafe_b64encode(encrypted_message).decode()
        )
    
    elif method == 'aes_gcm':
        salt = os.urandom(16)
        key = generate_key(password, salt)
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()
        tag = encryptor.tag
        encrypted_result = (
            base64.urlsafe_b64encode(salt).decode() + ':' +
            base64.urlsafe_b64encode(nonce).decode() + ':' +
            base64.urlsafe_b64encode(tag).decode() + ':' +
            base64.urlsafe_b64encode(encrypted_message).decode()
        )
    else:
        raise ValueError("Unsupported encryption method")

    encryption_time = time.time() - start_time  # Calculate encryption time
    return encrypted_result, encryption_time

def hash_sha256(message):
    """Hash a message using SHA-256 and measure the time taken."""
    start_time = time.time()
    sha256 = hashes.Hash(hashes.SHA256(), backend=default_backend())
    sha256.update(message.encode())
    hashed_message = base64.urlsafe_b64encode(sha256.finalize()).decode()
    sha256_time = time.time() - start_time  # Time taken for SHA-256 hashing
    return hashed_message, sha256_time

def hash_bcrypt(message):
    """Hash a message using bcrypt and measure the time taken."""
    start_time = time.time()
    salt = bcrypt.gensalt()
    hashed_message = bcrypt.hashpw(message.encode(), salt).decode()
    bcrypt_time = time.time() - start_time  # Time taken for bcrypt hashing
    return hashed_message, bcrypt_time

def process_message(method, message_content):
    # Perform encryption and measure time
    encrypted_content, encryption_time = encrypt_message(method, message_content)

    # Perform SHA-256 hashing and measure time
    hashed_sha256_content, sha256_time = hash_sha256(message_content)

    # Perform bcrypt hashing and measure time
    hashed_bcrypt_content, bcrypt_time = hash_bcrypt(message_content)

    # Calculate the total time
    total_time = encryption_time + sha256_time + bcrypt_time

    # Store in the database (assuming a Django model similar to the one you provided)
    message_instance = Message(
        content=message_content,
        encryption_method=method,
        encrypted_content=encrypted_content,
        hashed_content_sha256=hashed_sha256_content,
        hashed_content_bcrypt=hashed_bcrypt_content,
        encryption_time=encryption_time,
        hash_time=f"{sha256_time:.6f}:{bcrypt_time:.6f}",  # Store hash times in a single field
        total_time=total_time  # Add the total time
    )
    message_instance.save()

    return message_instance
