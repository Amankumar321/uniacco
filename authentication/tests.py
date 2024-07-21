from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient
from django.utils import timezone
from datetime import timedelta
from .models import User, OTP


class AuthenticationTests(TestCase):
    
    def setUp(self):
        self.client = APIClient()

    def test_register_user(self):
        url = reverse('register')
        data = {'email': 'test@example.com', 'password': 'testpassword'}

        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(User.objects.count(), 1)
        self.assertEqual(User.objects.get().email, 'test@example.com')

    def test_request_otp(self):
        # First, register a user
        user = User.objects.create_user(email='test@example.com', password='testpassword')

        # Request OTP for registered user
        url = reverse('request-otp')
        data = {'email': 'test@example.com'}

        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Check if OTP was created and stored in the database
        self.assertTrue(OTP.objects.filter(user_email='test@example.com').exists())

    def test_verify_otp(self):
        # Create a user and generate OTP
        user = User.objects.create_user(email='test@example.com', password='testpassword')
        OTP.create(user_email='test@example.com', validity_minutes=5)

        # Simulate verifying OTP
        url = reverse('verify-otp')
        data = {'email': 'test@example.com', 'otp': OTP.objects.get(user_email='test@example.com').otp_code}

        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Check if JWT token is returned in response
        self.assertIn('token', response.data)

    def test_invalid_otp(self):
        # Create a user without OTP
        user = User.objects.create_user(email='test@example.com', password='testpassword')

        # Attempt to verify OTP without generating it first
        url = reverse('verify-otp')
        data = {'email': 'test@example.com', 'otp': '123456'}  # Invalid OTP

        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], 'Invalid or expired OTP.')

    def test_expired_otp(self):
        # Create a user and generate expired OTP
        user = User.objects.create_user(email='test@example.com', password='testpassword')
        expired_time = timezone.now() - timedelta(minutes=10)
        OTP.objects.create(user_email='test@example.com', otp_code='123456', expiry_time=expired_time)

        # Attempt to verify expired OTP
        url = reverse('verify-otp')
        data = {'email': 'test@example.com', 'otp': '123456'}

        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], 'Invalid or expired OTP.')

    def test_user_not_found(self):
        # Attempt OTP verification for non-existent user
        url = reverse('verify-otp')
        data = {'email': 'nonexistent@example.com', 'otp': '123456'}

        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response.data['error'], 'User not found.')
