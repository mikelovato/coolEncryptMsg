import time  # To measure execution time
from django.http import HttpResponse
from django.shortcuts import render, redirect
from .forms import MessageForm
from .models import Message
from .encryption import encrypt_message, hash_sha256, hash_bcrypt  # Import encryption and hashing functions

def send_message(request):
    if request.method == 'POST':
        form = MessageForm(request.POST)
        if form.is_valid():
            content = form.cleaned_data['content']
            method = form.cleaned_data['encryption_method']

            # Encrypt the content
            encrypted_content, encryption_time = encrypt_message(method, content)

            # Hash using SHA-256
            hashed_content_sha256, sha256_hash_time = hash_sha256(content)

            # Hash using bcrypt
            hashed_content_bcrypt, bcrypt_hash_time = hash_bcrypt(content)

            # Save the message instance in the database
            Message.objects.create(
                content=content,
                encryption_method=method,
                encrypted_content=encrypted_content,
                hashed_content_sha256=hashed_content_sha256,
                hashed_content_bcrypt=hashed_content_bcrypt,
                encryption_time=encryption_time,
                sha256_hash_time=sha256_hash_time,
                bcrypt_hash_time=bcrypt_hash_time
            )

            return redirect('view_messages')
    else:
        form = MessageForm()

    return render(request, 'EncryptMsg/send_messages.html', {'form': form})
