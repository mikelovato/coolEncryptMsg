from django.db import models

class Message(models.Model):
    content = models.TextField()  # Original plaintext message
    encryption_method = models.CharField(max_length=50)  # Method used for encryption
    encrypted_content = models.TextField()  # Encrypted message content
    hashed_content_sha256 = models.CharField(max_length=64)  # SHA-256 hash (64 characters)
    hashed_content_sha3 = models.CharField(max_length=64)  # SHA-3 hash (64 characters)
    hashed_content_argon2 = models.TextField()  # Argon2 hash (variable length)
    hashed_content_scrypt = models.TextField()  # Scrypt hash (variable length)
    hashed_content_bcrypt = models.TextField()  # bcrypt hash (variable length)
    encryption_time = models.DecimalField(max_digits=10, decimal_places=6)  # Time spent on encryption
    sha256_hash_time = models.DecimalField(max_digits=10, decimal_places=6)  # Time spent on SHA-256 hashing
    sha3_hash_time = models.DecimalField(max_digits=10, decimal_places=6)  # Time spent on SHA-3 hashing
    argon2_hash_time = models.DecimalField(max_digits=10, decimal_places=6)  # Time spent on Argon2 hashing
    scrypt_hash_time = models.DecimalField(max_digits=10, decimal_places=6)  # Time spent on Scrypt hashing
    bcrypt_hash_time = models.DecimalField(max_digits=10, decimal_places=6)  # Time spent on bcrypt hashing

    def __str__(self):
        return f"{self.encryption_method} - {self.content[:20]}"
