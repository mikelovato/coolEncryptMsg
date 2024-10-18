from django import forms

class MessageForm(forms.Form):
    content = forms.CharField(widget=forms.Textarea)
    encryption_method = forms.ChoiceField(choices=[
        ('fernet', 'Fernet'),
        ('chacha20_poly1305', 'ChaCha20-Poly1305'),
        ('aes_cfb_256', 'AES (CFB Mode) - 256 Key size'),
        ('aes_ctr_256', 'AES (CTR Mode) - 256 Key size'),
        ('aes_gcm_256', 'AES (GCM Mode) - 256 Key size'),
    ])
