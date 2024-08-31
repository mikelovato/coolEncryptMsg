from django.db import models


class Message(models.Model):
    content = models.TextField()
    encryption_method = models.CharField(max_length=50)
    encrypted_content = models.TextField()

    def __str__(self):
        return f"{self.encryption_method} - {self.content[:20]}"
