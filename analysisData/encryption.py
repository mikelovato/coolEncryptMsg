import os
import base64
import bcrypt  # Import bcrypt for hashing
import time
import random
import string
from django.conf import settings
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Generate a random password by openssl: openssl rand -hex 16
pwdHex = '3f7333d9fc36808eab151de2ada6bfc3'
password = bytes.fromhex(pwdHex) # Define the password that will be used for key derivation

# Function to generate a key using PBKDF2HMAC
def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes for AES-256
        salt=salt,
        iterations=480000,
    )
    return kdf.derive(password)  # Return raw key bytes for AES

# Generate a random salt for encrytion
salt = os.urandom(16)

# Generate a key using random salt and password
key = generate_key(password, salt)

# Generate a 16 bytes IV for cfb or nonce for ctr
iv = os.urandom(16)

# Generate a 12 bytes nonce for gcm
nonce = os.urandom(12)

# Encrytor
def EncryptMessage(method, message):
    res = ""
    start_time = time.time()
    if method == 'aes_cfb': # AES encryption using CFB mode
         # Create the cipher method for using AES in CFB mode
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Using cipher method to encrypt plaintext
        encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()
        
        # Return salt, IV, and encrypted message (concatenated with ':')
        res = 'EmptyTag:' + base64.urlsafe_b64encode(iv).decode() + ':' + base64.urlsafe_b64encode(encrypted_message).decode()

    elif method == 'aes_ecb': # AES encryption using ECB mode
        # Create the cipher method for using ECB in CTR mode
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()

        # Using cipher method to encrypt plaintext
        encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()
        
        # Return salt, nonce, and encrypted message of using aes ECB mode
        res = 'EmptyTag:' + base64.urlsafe_b64encode(iv).decode() + ':' +  base64.urlsafe_b64encode(encrypted_message).decode()

    elif method == 'aes_cbc': # AES encryption using CBC mode
        # Create the cipher method for using CBC in CTR mode
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Using cipher method to encrypt plaintext
        encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()
        
        # Return salt, nonce, and encrypted message of using aes CTR mode
        res = 'EmptyTag:' + base64.urlsafe_b64encode(iv).decode() + ':' + base64.urlsafe_b64encode(encrypted_message).decode()

    elif method == 'aes_ctr': # AES encryption using CTR mode
        # Create the cipher method for using AES in CTR mode
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Using cipher method to encrypt plaintext
        encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()
        
        # Return salt, nonce, and encrypted message of using aes CTR mode
        res = 'EmptyTag:' + base64.urlsafe_b64encode(iv).decode() + ':' + base64.urlsafe_b64encode(encrypted_message).decode()

    elif method == 'aes_gcm': # AES encryption using GCM mode
        # Create the cipher method for using AES in GCM mode
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()

        # Using cipher method to encrypt plaintext
        encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()
        
        # Getting the tag of the GCM mode for authentication and verification
        tag = encryptor.tag

        # Return salt, nonce, tag and encrypted message of using aes GCM mode
        res = base64.urlsafe_b64encode(tag).decode() + ':' + base64.urlsafe_b64encode(nonce).decode() + ':' + base64.urlsafe_b64encode(encrypted_message).decode()

    else:
        raise ValueError("Unsupported encryption method")

    elapsed_time = time.time() - start_time
    # print("--- Encrypt method %s with %0.20f milliseconds ---" % (method, elapsed_time * 1000))
    return res, elapsed_time

# Decryptor
def DecryptMessage(method, encrypted_message):
    res = ""
    start_time = time.time()

    # Split the salt, nonce or iv, tag and ciphertext from the encrypted message
    tag_b64, nonce_b64, ciphertext_b64 = encrypted_message.split(':')
    tag = base64.urlsafe_b64decode(tag_b64)
    nonce = base64.urlsafe_b64decode(nonce_b64)
    ciphertext = base64.urlsafe_b64decode(ciphertext_b64)

    if method == 'aes_cfb':
        # Generate the decryptor for the message using AES in CFB mode
        cipher = Cipher(algorithms.AES(key), modes.CFB(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        res = (decryptor.update(ciphertext) + decryptor.finalize()).decode()

    elif method == 'aes_ecb':
        # Generate the decryptor for the message using AES in ECB mode
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the ciphertext by using decryptor
        res = (decryptor.update(ciphertext) + decryptor.finalize()).decode()

    elif method == 'aes_cbc':
        # Generate the decryptor for the message using AES in CBC mode
        cipher = Cipher(algorithms.AES(key), modes.CBC(nonce), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the ciphertext by using decryptor
        res = (decryptor.update(ciphertext) + decryptor.finalize()).decode()

    elif method == 'aes_ctr':
        # Generate the decryptor for the message using AES in CTR mode
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the ciphertext by using decryptor
        res = (decryptor.update(ciphertext) + decryptor.finalize()).decode()

    elif method == 'aes_gcm':
        # Generate the decryptor for the message using AES in GCM mode
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the ciphertext by using decryptor
        res = (decryptor.update(ciphertext) + decryptor.finalize()).decode()

    else:
        return 'Unsupported encryption method'

    elapsed_time = time.time() - start_time
    # print("--- Decrypt method %s with %0.20f milliseconds with res %s ---" % (method, elapsed_time * 1000, res))
    return res, elapsed_time

def CmpStringMatch(str1, str2):
    if str1 == str2:
        return "MATCH"
    else:
        return "NOT MATCH"

def EncryDecryMethWithLength(length):
    print("------ size %0.1f MB" % (length / 1048576))

    baseCharacters = string.ascii_letters + string.digits + string.punctuation
    random_string = ''.join(random.choice(baseCharacters) for _ in range(length))

    cfbEncyLst = []
    ecbEncyLst = []
    cbcEncyLst = []
    ctrEncyLst = []
    gcmEncyLst = []

    cfbEncyTimeLst = []
    ecbEncyTimeLst = []
    cbcEncyTimeLst = []
    ctrEncyTimeLst = []
    gcmEncyTimeLst = []

    cfbDecyLst = []
    ecbDecyLst = []
    cbcDecyLst = []
    ctrDecyLst = []
    gcmDecyLst = []

    cfbDecyTimeLst = []
    ecbDecyTimeLst = []
    cbcDecyTimeLst = []
    ctrDecyTimeLst = []
    gcmDecyTimeLst = []

    for i in range(10):
        cfbEncy, cfbEncyTime = EncryptMessage('aes_cfb', random_string)
        ecbEncy, ecbEncyTime = EncryptMessage('aes_ecb', random_string)
        cbcEncy, cbcEncyTime = EncryptMessage('aes_cbc', random_string)
        ctrEncy, ctrEncyTime = EncryptMessage('aes_ctr', random_string)
        gcmEncy, gcmEncyTime = EncryptMessage('aes_gcm', random_string)
        cfbEncyLst.append(cfbEncy)
        ecbEncyLst.append(ecbEncy)
        cbcEncyLst.append(cbcEncy)
        ctrEncyLst.append(ctrEncy)
        gcmEncyLst.append(gcmEncy)
        cfbEncyTimeLst.append(cfbEncyTime)
        ecbEncyTimeLst.append(ecbEncyTime)
        cbcEncyTimeLst.append(cbcEncyTime)
        ctrEncyTimeLst.append(ctrEncyTime)
        gcmEncyTimeLst.append(gcmEncyTime)

    for i in range(10):
        cfbDecy, cfbDecyTime = DecryptMessage('aes_cfb', cfbEncyLst[i])
        ecbDecy, ecbDecyTime = DecryptMessage('aes_ecb', ecbEncyLst[i])
        cbcDecy, cbcDecyTime = DecryptMessage('aes_cbc', cbcEncyLst[i])
        ctrDecy, ctrDecyTime = DecryptMessage('aes_ctr', ctrEncyLst[i])
        gcmDecy, gcmDecyTime = DecryptMessage('aes_gcm', gcmEncyLst[i])
        cfbDecyLst.append(cfbDecy)
        ecbDecyLst.append(ecbDecy)
        cbcDecyLst.append(cbcDecy)
        ctrDecyLst.append(ctrDecy)
        gcmDecyLst.append(gcmDecy)
        cfbDecyTimeLst.append(cfbDecyTime)
        ecbDecyTimeLst.append(ecbDecyTime)
        cbcDecyTimeLst.append(cbcDecyTime)
        ctrDecyTimeLst.append(ctrDecyTime)
        gcmDecyTimeLst.append(gcmDecyTime)

    cfbEncyTimeSumTime = 0.0
    ecbEncyTimeSumTime = 0.0
    cbcEncyTimeSumTime = 0.0
    ctrEncyTimeSumTime = 0.0
    gcmEncyTimeSumTime = 0.0
    cfbDecyTimeSumTime = 0.0
    ecbDecyTimeSumTime = 0.0
    cbcDecyTimeSumTime = 0.0
    ctrDecyTimeSumTime = 0.0
    gcmDecyTimeSumTime = 0.0

    for i in range(10):
        cfbEncyTimeSumTime += cfbEncyTimeLst[i]
        ecbEncyTimeSumTime += ecbEncyTimeLst[i]
        cbcEncyTimeSumTime += cbcEncyTimeLst[i]
        ctrEncyTimeSumTime += ctrEncyTimeLst[i]
        gcmEncyTimeSumTime += gcmEncyTimeLst[i]
        cfbDecyTimeSumTime += cfbDecyTimeLst[i]
        ecbDecyTimeSumTime += ecbDecyTimeLst[i]
        cbcDecyTimeSumTime += cbcDecyTimeLst[i]
        ctrDecyTimeSumTime += ctrDecyTimeLst[i]
        gcmDecyTimeSumTime += gcmDecyTimeLst[i]        

    print(" --- cfb : avg encry time %0.20fms" % (cfbEncyTimeSumTime * 1000 / 10))
    print(" --- cfb : avg decry time %0.20fms" % (cfbDecyTimeSumTime * 1000 / 10))
    print(" --- cfb : list of encry tiime")
    [print("          %0.20f" % (item * 1000)) for item in cfbEncyTimeLst]
    print(" --- cfb : list of decry tiime")
    [print("          %0.20f" % (item * 1000)) for item in cfbDecyTimeLst]

    print(" --- ecb : avg encry time %0.20fms" % (ecbEncyTimeSumTime * 1000 / 10))
    print(" --- ecb : avg decry time %0.20fms" % (ecbDecyTimeSumTime * 1000 / 10))
    print(" --- ecb : list of encry tiime")
    [print("          %0.20f" % (item * 1000)) for item in ecbEncyTimeLst]
    print(" --- ecb : list of decry tiime")
    [print("          %0.20f" % (item * 1000)) for item in ecbDecyTimeLst]

    print(" --- cbc : avg encry time %0.20fms" % (cbcEncyTimeSumTime * 1000 / 10))
    print(" --- cbc : avg decry time %0.20fms" % (cbcDecyTimeSumTime * 1000 / 10))
    print(" --- cbc : list of encry tiime")
    [print("          %0.20f" % (item * 1000)) for item in cbcEncyTimeLst]
    print(" --- cbc : list of decry tiime")
    [print("          %0.20f" % (item * 1000)) for item in cbcDecyTimeLst]

    print(" --- ctr : avg encry time %0.20fms" % (ctrEncyTimeSumTime * 1000 / 10))
    print(" --- ctr : avg decry time %0.20fms" % (ctrDecyTimeSumTime * 1000 / 10))
    print(" --- ctr : list of encry tiime")
    [print("          %0.20f" % (item * 1000)) for item in ctrEncyTimeLst]
    print(" --- ctr : list of decry tiime")
    [print("          %0.20f" % (item * 1000)) for item in ctrDecyTimeLst]

    print(" --- gcm : avg encry time %0.20fms" % (gcmEncyTimeSumTime * 1000 / 10))
    print(" --- gcm : avg decry time %0.20fms" % (gcmDecyTimeSumTime * 1000 / 10))
    print(" --- gcm : list of encry tiime")
    [print("          %0.20f" % (item * 1000)) for item in gcmEncyTimeLst]
    print(" --- gcm : list of decry tiime")
    [print("          %0.20f" % (item * 1000)) for item in gcmDecyTimeLst]

def IncreasingMsgLength(MaxiPower):
    base = 1048576
    for i in range(1, MaxiPower):
        EncryDecryMethWithLength(i * base)

IncreasingMsgLength(21)