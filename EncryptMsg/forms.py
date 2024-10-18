from django import forms

class MessageForm(forms.Form):
    content = forms.CharField(widget=forms.Textarea)
    encryption_method = forms.ChoiceField(choices=[
        ('fernet', 'Fernet'),
        ('chacha20_poly1305', 'ChaCha20-Poly1305'),
        ('aes_cfb_128', 'AES (CFB Mode) - 128 Key size'),
        ('aes_cfb_256', 'AES (CFB Mode) - 256 Key size'),
        ('aes_cfb_384', 'AES (CFB Mode) - 384 Key size'),
        ('aes_cfb_512', 'AES (CFB Mode) - 512 Key size'),
        ('aes_ctr_128', 'AES (CTR Mode) - 128 Key size'),
        ('aes_ctr_256', 'AES (CTR Mode) - 256 Key size'),
        ('aes_ctr_384', 'AES (CTR Mode) - 384 Key size'),
        ('aes_ctr_512', 'AES (CTR Mode) - 512 Key size'),
        ('aes_gcm_128', 'AES (GCM Mode) - 128 Key size'),
        ('aes_gcm_256', 'AES (GCM Mode) - 256 Key size'),
        ('aes_gcm_384', 'AES (GCM Mode) - 384 Key size'),
        ('aes_gcm_512', 'AES (GCM Mode) - 512 Key size'),
    ])
