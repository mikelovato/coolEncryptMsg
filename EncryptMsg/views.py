from django.http import HttpResponse
from django.shortcuts import render, redirect
from .forms import MessageForm
from .models import Message
from .encryption import encrypt_message, decrypt_message
import hashlib  # For SHA-256 hashing
import bcrypt  # For bcrypt hashing

def send_message(request):
    if request.method == 'POST':
        form = MessageForm(request.POST)
        if form.is_valid():
            content = form.cleaned_data['content']
            method = form.cleaned_data['encryption_method']

            # Encrypt the content
            encrypted_content = encrypt_message(method, content)

            # Hash the content using SHA-256
            hashed_content_sha256 = hashlib.sha256(content.encode()).hexdigest()

            # Hash the content using bcrypt
            hashed_content_bcrypt = bcrypt.hashpw(content.encode(), bcrypt.gensalt()).decode()

            # Save the content, encryption method, encrypted content, hashed content (SHA-256), and hashed content (bcrypt) to the database
            Message.objects.create(
                content=content, 
                encryption_method=method, 
                encrypted_content=encrypted_content,
                hashed_content_sha256=hashed_content_sha256,  # SHA-256 hash
                hashed_content_bcrypt=hashed_content_bcrypt   # bcrypt hash
            )

            return redirect('view_messages')
    else:
        form = MessageForm()
    
    return render(request, 'EncryptMsg/send_messages.html', {'form': form})  


def view_messages(request):
    messages = Message.objects.all()
    decrypted_messages = []
    for msg in messages:
        try:
            decrypted_content = decrypt_message(msg.encryption_method, msg.encrypted_content)
        except Exception as e:
            decrypted_content = f"Error decrypting: {str(e)}"
        
        decrypted_messages.append({
            'content': decrypted_content,
            'encryption_method': msg.encryption_method
        })
    
    return render(request, 'EncryptMsg/view_messages.html', {'messages': decrypted_messages})  


def view_summary_messages(request):
    messages = Message.objects.all()
    summary_messages = [
        {
            'content': msg.content,               # The original content (plaintext)
            'encrypted_content': msg.encrypted_content,  # The encrypted content (ciphertext)
            'encryption_method': msg.encryption_method,  # The encryption method (e.g., 'fernet', 'aes_cfb')
            'hashed_content_sha256': msg.hashed_content_sha256,  # SHA-256 hash
            'hashed_content_bcrypt': msg.hashed_content_bcrypt  # bcrypt hash
        }
        for msg in messages
    ]
    return render(request, 'EncryptMsg/view_summary_messages.html', {'messages': summary_messages})
