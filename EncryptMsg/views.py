import time  # To measure execution time
from django.http import HttpResponse
from django.shortcuts import render, redirect
from .forms import MessageForm
from .models import Message
from .encryption import encrypt_message, decrypt_message, hash_sha256, hash_bcrypt  # Import hashing functions

def send_message(request):
    if request.method == 'POST':
        form = MessageForm(request.POST)
        if form.is_valid():
            content = form.cleaned_data['content']
            method = form.cleaned_data['encryption_method']

            # Measure time for encryption
            encryption_start_time = time.time()
            encrypted_content = encrypt_message(method, content)
            encryption_end_time = time.time()
            encryption_time = encryption_end_time - encryption_start_time  # Time spent on encryption

            # Measure time for SHA-256 hashing
            sha256_start_time = time.time()
            hashed_content_sha256 = hash_sha256(content)
            sha256_end_time = time.time()
            sha256_hash_time = sha256_end_time - sha256_start_time  # Time spent on SHA-256 hashing

            # Measure time for bcrypt hashing
            bcrypt_start_time = time.time()
            hashed_content_bcrypt = hash_bcrypt(content)
            bcrypt_end_time = time.time()
            bcrypt_hash_time = bcrypt_end_time - bcrypt_start_time  # Time spent on bcrypt hashing

            # Save the content, encryption method, encrypted content, hashed content (SHA-256), hashed content (bcrypt), and timing info to the database
            Message.objects.create(
                content=content, 
                encryption_method=method, 
                encrypted_content=encrypted_content,
                hashed_content_sha256=hashed_content_sha256,  # SHA-256 hash
                hashed_content_bcrypt=hashed_content_bcrypt,   # bcrypt hash
                encryption_time=encryption_time,               # Time spent on encryption
                sha256_hash_time=sha256_hash_time,             # Time spent on SHA-256 hashing
                bcrypt_hash_time=bcrypt_hash_time              # Time spent on bcrypt hashing
            )

            return redirect('view_messages')
    else:
        form = MessageForm()

    return render(request, 'EncryptMsg/send_messages.html', {'form': form})
