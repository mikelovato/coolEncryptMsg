from cryptography.fernet import Fernet
from django.conf import settings
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

password = b"passwordexample"
salt = bytes(b'0')
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=480000,
)
settings.FERNET_KEY = base64.urlsafe_b64encode(kdf.derive(password))

# Generate a key for Fernet encryption (store this securely)
# settings.FERNET_KEY = Fernet.generate_key()

fernet = Fernet(settings.FERNET_KEY)


def encrypt_message(method, message):
    if method == 'fernet':
        return fernet.encrypt(message.encode()).decode()
    elif method == 'symmetric':
        # Implement another symmetric encryption here if needed
        return fernet.encrypt(message.encode()).decode()
    else:
        raise ValueError("Unsupported encryption method")


def decrypt_message(method, encrypted_message):
    if method == 'fernet':
        return fernet.decrypt(encrypted_message.encode()).decode()
    elif method == 'symmetric':
        # Implement the corresponding decryption here if needed
        return fernet.decrypt(encrypted_message.encode()).decode()
    else:
        raise ValueError("Unsupported decryption method")
