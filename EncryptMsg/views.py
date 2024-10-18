from django.shortcuts import render, redirect
from .models import Message
from .forms import MessageForm
from .encryption import (
    encrypt_message, 
    hash_sha256, 
    hash_sha3_256,
    hash_argon2,
    hash_scrypt,
    hash_bcrypt
)

def send_message(request):
    if request.method == 'POST':
        form = MessageForm(request.POST)
        if form.is_valid():
            content = form.cleaned_data['content']
            method = form.cleaned_data['encryption_method']

            try:
                # Encrypt the content
                encrypted_content, encryption_time = encrypt_message(method, content)

                # Hash using SHA-256
                hashed_content_sha256, sha256_hash_time = hash_sha256(content)

                # Hash using SHA-3
                hashed_content_sha3, sha3_hash_time = hash_sha3_256(content)

                # Hash using Argon2
                hashed_content_argon2, argon2_hash_time = hash_argon2(content)

                # Hash using Scrypt
                hashed_content_scrypt, scrypt_hash_time = hash_scrypt(content)

                # Hash using bcrypt
                hashed_content_bcrypt, bcrypt_hash_time = hash_bcrypt(content)

                # Save the message instance in the database
                Message.objects.create(
                    content=content,
                    encryption_method=method,
                    encrypted_content=encrypted_content,
                    hashed_content_sha256=hashed_content_sha256,
                    hashed_content_sha3=hashed_content_sha3,  # New SHA-3 hash field
                    hashed_content_argon2=hashed_content_argon2,  # New Argon2 hash field
                    hashed_content_scrypt=hashed_content_scrypt,  # New Scrypt hash field
                    hashed_content_bcrypt=hashed_content_bcrypt,
                    encryption_time=encryption_time,
                    sha256_hash_time=sha256_hash_time,
                    sha3_hash_time=sha3_hash_time,  # New SHA-3 time field
                    argon2_hash_time=argon2_hash_time,  # New Argon2 time field
                    scrypt_hash_time=scrypt_hash_time,  # New Scrypt time field
                    bcrypt_hash_time=bcrypt_hash_time
                )

                return redirect('view_summary_messages')  # Redirect to summary view after successful message
            except Exception as e:
                # Log the error or handle it as needed
                print(f"Error occurred: {e}")
                form.add_error(None, "An error occurred while processing your request.")
    else:
        form = MessageForm()

    return render(request, 'EncryptMsg/send_messages.html', {'form': form})

def view_messages(request):
    messages = Message.objects.all()  # Retrieve all messages from the database
    return render(request, 'EncryptMsg/view_messages.html', {'messages': messages})

def view_summary_messages(request):
    messages = Message.objects.all()
    summary_messages = [
        {
            'content': msg.content,                       # The original content (plaintext)
            'encrypted_content': msg.encrypted_content,   # The encrypted content (ciphertext)
            'encryption_method': msg.encryption_method,   # The encryption method (e.g., 'fernet', 'aes_cfb')
            'hashed_content_sha256': msg.hashed_content_sha256,  # SHA-256 hash
            'hashed_content_sha3': msg.hashed_content_sha3,  # SHA-3 hash
            'hashed_content_argon2': msg.hashed_content_argon2,  # Argon2 hash
            'hashed_content_scrypt': msg.hashed_content_scrypt,  # Scrypt hash
            'hashed_content_bcrypt': msg.hashed_content_bcrypt,   # bcrypt hash
            'encryption_time': msg.encryption_time,       # Time taken for encryption
            'sha256_hash_time': msg.sha256_hash_time,     # Time taken for SHA-256 hashing
            'sha3_hash_time': msg.sha3_hash_time,         # Time taken for SHA-3 hashing
            'argon2_hash_time': msg.argon2_hash_time,     # Time taken for Argon2 hashing
            'scrypt_hash_time': msg.scrypt_hash_time,     # Time taken for Scrypt hashing
            'bcrypt_hash_time': msg.bcrypt_hash_time,      # Time taken for bcrypt hashing
        }
        for msg in messages
    ]
    return render(request, 'EncryptMsg/view_summary_messages.html', {'messages': summary_messages})
