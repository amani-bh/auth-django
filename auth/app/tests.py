from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from .models import User
from .serializers import UserSerializer


class UserAPITestCase(APITestCase):
    def setUp(self):
        user_data = {
            'email': 'test@example.com',
            'password': 'password',
            'phone': '1234567890',
            'first_name': 'test',
            'last_name': 'test',
            'is_active': True
        }
        serializer = UserSerializer(data=user_data)
        serializer.is_valid(raise_exception=True)
        self.user = serializer.save()
        self.client.force_authenticate(user=self.user)

    def test_register(self):
        url = reverse('register')
        data = {
            'email': 'newuser@example.com',
            'password': 'password',
            'phone': '1234567890',
            'first_name': 'test',
            'last_name': 'test'
        }
        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_login(self):
        url = reverse('login')
        data = {
            'email': 'test@example.com',
            'password': 'password'
        }
        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data)

