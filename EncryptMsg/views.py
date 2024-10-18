from django.http import HttpResponse
from django.shortcuts import render, redirect
from .forms import MessageForm
from .models import Message
from .encryption import process_message  # Import your processing function

def send_message(request):
    if request.method == 'POST':
        form = MessageForm(request.POST)
        if form.is_valid():
            content = form.cleaned_data['content']
            method = form.cleaned_data['encryption_method']

            try:
                # Process the message which includes encryption and hashing
                message_instance = process_message(method, content)

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
            'content': msg.content,
            'encrypted_content': msg.encrypted_content,
            'encryption_method': msg.encryption_method,
            'hashed_content_sha256': msg.hashed_content_sha256,
            'hashed_content_sha3': msg.hashed_content_sha3,
            'hashed_content_argon2': msg.hashed_content_argon2,
            'hashed_content_scrypt': msg.hashed_content_scrypt,
            'hashed_content_bcrypt': msg.hashed_content_bcrypt,
            'encryption_time': msg.encryption_time,
            'sha256_hash_time': msg.sha256_hash_time,
            'sha3_hash_time': msg.sha3_hash_time,
            'argon2_hash_time': msg.argon2_hash_time,
            'scrypt_hash_time': msg.scrypt_hash_time,
            'bcrypt_hash_time': msg.bcrypt_hash_time,
        }
        for msg in messages
    ]
    return render(request, 'EncryptMsg/view_summary_messages.html', {'messages': summary_messages})
