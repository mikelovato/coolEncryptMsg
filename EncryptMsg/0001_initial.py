# Generated by Django 5.1.2 on 2024-10-18 07:47

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Message',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('content', models.TextField()),
                ('encryption_method', models.CharField(max_length=50)),
                ('encrypted_content', models.TextField()),
                ('hashed_content_sha256', models.CharField(max_length=64)),
                ('hashed_content_sha3', models.CharField(max_length=64)),
                ('hashed_content_argon2', models.TextField()),
                ('hashed_content_scrypt', models.TextField()),
                ('hashed_content_bcrypt', models.TextField()),
                ('encryption_time', models.DecimalField(decimal_places=6, max_digits=10)),
                ('sha256_hash_time', models.DecimalField(decimal_places=6, max_digits=10)),
                ('sha3_hash_time', models.DecimalField(decimal_places=6, max_digits=10)),
                ('argon2_hash_time', models.DecimalField(decimal_places=6, max_digits=10)),
                ('scrypt_hash_time', models.DecimalField(decimal_places=6, max_digits=10)),
                ('bcrypt_hash_time', models.DecimalField(decimal_places=6, max_digits=10)),
            ],
        ),
    ]