from django.http import HttpResponse
from django.shortcuts import render, redirect
from .forms import MessageForm
from .models import Message
from .encryption import encrypt_message, decrypt_message


def send_message(request):
    if request.method == 'POST':
        form = MessageForm(request.POST)
        if form.is_valid():
            content = form.cleaned_data['content']
            method = form.cleaned_data['encryption_method']
            encrypted_content = encrypt_message(method, content)
            Message.objects.create(
                content=content, encryption_method=method, encrypted_content=encrypted_content)
            return redirect('view_messages')
    else:
        form = MessageForm()
    return render(request, 'EncryptMsg/send_massages.html', {'form': form})


def view_messages(request):
    messages = Message.objects.all()
    decrypted_messages = [
        {
            'content': decrypt_message(msg.encryption_method, msg.encrypted_content),
            'encryption_method': msg.encryption_method
        }
        for msg in messages
    ]
    return render(request, 'EncryptMsg/view_massages.html', {'messages': decrypted_messages})
