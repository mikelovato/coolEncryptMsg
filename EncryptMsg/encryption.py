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
from argon2 import PasswordHasher  # Import Argon2
from cryptography.hazmat.primitives import hashes as hash_algorithms  # For SHA-3

# Example password for key generation
password = b"passwordexample"

# Function to generate a key using PBKDF2HMAC
def generate_key_128(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # SHA-256 is still appropriate
        length=16,  # 16 bytes for a 128-bit key
        salt=salt,
        iterations=480000,
        backend=default_backend(),
    )
    return kdf.derive(password)

def generate_key_256(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes for AES-256
        salt=salt,
        iterations=480000,
        backend=default_backend(),
    )
    return kdf.derive(password)

def generate_key_384(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA384(),  # Use SHA-384 for a 384-bit key
        length=48,  # 48 bytes for a 384-bit key
        salt=salt,
        iterations=480000,
        backend=default_backend(),
    )
    return kdf.derive(password)

def generate_key_512(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),  # Use SHA-512 for a 512-bit key
        length=64,  # 64 bytes for a 512-bit key
        salt=salt,
        iterations=480000,
        backend=default_backend(),
    )
    return kdf.derive(password)

def encrypt_message(method, message):
    start_time = time.perf_counter()  # Use high-resolution timer

    if method == 'fernet':
        salt = os.urandom(16)
        key = base64.urlsafe_b64encode(generate_key_256(password, salt)).decode()
        fernet = Fernet(key)
        nonce = os.urandom(16)
        message_with_nonce = nonce + message.encode()
        encrypted_message = fernet.encrypt(message_with_nonce)
        encrypted_result = (
            base64.urlsafe_b64encode(nonce).decode() + ':' +
            base64.urlsafe_b64encode(salt).decode() + ':' +
            encrypted_message.decode()
        )
    
    elif method == 'aes_cfb_256':
        salt = os.urandom(16)
        key = generate_key_256(password, salt)
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
    
    elif method == 'aes_ctr_256':
        salt = os.urandom(16)
        key = generate_key_256(password, salt)
        nonce = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()
        encrypted_result = (
            base64.urlsafe_b64encode(salt).decode() + ':' +
            base64.urlsafe_b64encode(nonce).decode() + ':' +
            base64.urlsafe_b64encode(encrypted_message).decode()
        )
    
    elif method == 'aes_gcm_256':
        salt = os.urandom(16)
        key = generate_key_256(password, salt)
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

    elif method == 'aes_cfb_128':
        salt = os.urandom(16)
        key = generate_key_128(password, salt)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()
        encrypted_result = (
            base64.urlsafe_b64encode(salt).decode() + ':' +
            base64.urlsafe_b64encode(iv).decode() + ':' +
            base64.urlsafe_b64encode(encrypted_message).decode()
        )

    elif method == 'aes_cfb_384':
        salt = os.urandom(16)
        key = generate_key_384(password, salt)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()
        encrypted_result = (
            base64.urlsafe_b64encode(salt).decode() + ':' +
            base64.urlsafe_b64encode(iv).decode() + ':' +
            base64.urlsafe_b64encode(encrypted_message).decode()
        )

    elif method == 'aes_cfb_512':
        salt = os.urandom(16)
        key = generate_key_512(password, salt)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()
        encrypted_result = (
            base64.urlsafe_b64encode(salt).decode() + ':' +
            base64.urlsafe_b64encode(iv).decode() + ':' +
            base64.urlsafe_b64encode(encrypted_message).decode()
        )
    
    elif method == 'aes_ctr_128':
        salt = os.urandom(16)
        key = generate_key_128(password, salt)
        nonce = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()
        encrypted_result = (
            base64.urlsafe_b64encode(salt).decode() + ':' +
            base64.urlsafe_b64encode(nonce).decode() + ':' +
            base64.urlsafe_b64encode(encrypted_message).decode()
        )

    elif method == 'aes_ctr_384':
        salt = os.urandom(16)
        key = generate_key_384(password, salt)
        nonce = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()
        encrypted_result = (
            base64.urlsafe_b64encode(salt).decode() + ':' +
            base64.urlsafe_b64encode(nonce).decode() + ':' +
            base64.urlsafe_b64encode(encrypted_message).decode()
        )

    elif method == 'aes_ctr_512':
        salt = os.urandom(16)
        key = generate_key_512(password, salt)
        nonce = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()
        encrypted_result = (
            base64.urlsafe_b64encode(salt).decode() + ':' +
            base64.urlsafe_b64encode(nonce).decode() + ':' +
            base64.urlsafe_b64encode(encrypted_message).decode()
        )

    elif method == 'aes_gcm_128':
        salt = os.urandom(16)
        key = generate_key_128(password, salt)
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
        
    elif method == 'aes_gcm_384':
        salt = os.urandom(16)
        key = generate_key_384(password, salt)
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

    elif method == 'aes_gcm_512':
        salt = os.urandom(16)
        key = generate_key_512(password, salt)
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

    encryption_time = time.perf_counter() - start_time  # Calculate encryption time
    return encrypted_result, encryption_time

def hash_sha256(message):
    """Hash a message using SHA-256 and measure the time taken."""
    start_time = time.perf_counter()  # Use high-resolution timer
    sha256 = hashes.Hash(hashes.SHA256(), backend=default_backend())
    sha256.update(message.encode())
    hashed_message = base64.urlsafe_b64encode(sha256.finalize()).decode()
    sha256_time = time.perf_counter() - start_time  # Time taken for SHA-256 hashing
    return hashed_message, sha256_time

def hash_sha3_256(message):
    """Hash a message using SHA-3 and measure the time taken."""
    start_time = time.perf_counter()
    sha3_256 = hashes.Hash(hash_algorithms.SHA3_256(), backend=default_backend())
    sha3_256.update(message.encode())
    hashed_message = base64.urlsafe_b64encode(sha3_256.finalize()).decode()
    sha3_time = time.perf_counter() - start_time  # Time taken for SHA-3 hashing
    return hashed_message, sha3_time

def hash_argon2(message):
    """Hash a message using Argon2 and measure the time taken."""
    start_time = time.perf_counter()  # Use high-resolution timer
    ph = PasswordHasher()
    hashed_message = ph.hash(message)
    argon2_time = time.perf_counter() - start_time  # Time taken for Argon2 hashing
    return hashed_message, argon2_time

def hash_scrypt(message):
    """Hash a message using Scrypt and measure the time taken."""
    start_time = time.perf_counter()  # Use high-resolution timer
    salt = os.urandom(16)
    hashed_message = bcrypt.kdf(message.encode(), salt, 32, 2 ** 14)
    scrypt_time = time.perf_counter() - start_time  # Time taken for Scrypt hashing
    return hashed_message, scrypt_time

def hash_bcrypt(message):
    """Hash a message using bcrypt and measure the time taken."""
    start_time = time.perf_counter()  # Use high-resolution timer
    salt = bcrypt.gensalt()
    hashed_message = bcrypt.hashpw(message.encode(), salt).decode()
    bcrypt_time = time.perf_counter() - start_time  # Time taken for bcrypt hashing
    return hashed_message, bcrypt_time

    # Store in the database (assuming a Django model similar to the one you provided)
    message_instance = Message(
        content=message_content,
        encryption_method=method,
        encrypted_content=encrypted_content,
        hashed_content_sha256=hashed_sha256_content,
        hashed_content_sha3=hashed_sha3_content,  # Store SHA-3 hash
        hashed_content_argon2=hashed_argon2_content,  # Store Argon2 hash
        hashed_content_scrypt=hashed_scrypt_content,  # Store Scrypt hash
        hashed_content_bcrypt=hashed_bcrypt_content,
        encryption_time=encryption_time,
        hash_time=(
            f"{sha256_time:.6f}:{sha3_time:.6f}:" +
            f"{argon2_time:.6f}:{scrypt_time:.6f}:" +
            f"{bcrypt_time:.6f}"  # Store all hash times in a single field
        ),
        total_time=total_time  # Add the total time
    )
    message_instance.save()

    return message_instance
