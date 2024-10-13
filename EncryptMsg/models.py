from django.db import models

class Message(models.Model):
    content = models.TextField()  # Original plaintext message
    encryption_method = models.CharField(max_length=50)  # Method used for encryption
    encrypted_content = models.TextField()  # Encrypted message content
    hashed_content_sha256 = models.CharField(max_length=64)  # SHA-256 hash (64 characters)
    hashed_content_bcrypt = models.TextField()  # bcrypt hash (variable length)

    def __str__(self):
        return f"{self.encryption_method} - {self.content[:20]}"
