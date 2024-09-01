from django.test import TestCase, Client
from django.urls import reverse
from .models import Message


class MessageViewTests(TestCase):
    def setUp(self):
        # Create a client instance
        self.client = Client()
        # Create a test message
        self.message = Message.objects.create(
            content="Test message", encrypted_content="Encrypted message")

    def test_send_message_and_view(self):
        # Test sending a message
        response = self.client.post(reverse('send_message'), {
            'content': 'New test message',
            'encryption_method': 'fernet',
            'csrfmiddlewaretoken': 'dRcg3XC2Nwwq0BI2cjZopQWjHy1XTgmc1PAhOj0DykrFFvioH6qawXhHxGWPltJg',
        })
        # Assuming it redirects after successful post
        self.assertEqual(response.status_code, 302)
        # self.assertTrue(Message.objects.filter(content='New test message').exists())
        response = self.client.get(reverse('view_messages'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "New test message")

    def test_send_message_view(self):
        response = self.client.get(reverse('send_message'))
        self.assertEqual(response.status_code, 200)
