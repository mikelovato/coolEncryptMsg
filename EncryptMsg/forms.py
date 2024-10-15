from django import forms

class MessageForm(forms.Form):
    content = forms.CharField(widget=forms.Textarea)
    encryption_method = forms.ChoiceField(choices=[
        ('fernet', 'Fernet'),
        ('aes_cfb', 'AES (CFB Mode)'),
        ('aes_ctr', 'AES (CTR Mode)'),
        ('aes_gcm', 'AES (GCM Mode)'),
        ('chacha20_poly1305', 'ChaCha20-Poly1305'),
    ])
