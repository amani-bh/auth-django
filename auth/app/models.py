from django.db import models
from django.contrib.auth.models import AbstractUser


# Create your models here.

class User(AbstractUser):
    phone=models.CharField(max_length=15)
    email = models.CharField(max_length=255, unique=True)
    password = models.CharField(max_length=255)
    badge = models.CharField(max_length=255)
    is_active = models.BooleanField(default=False)
    private = models.BooleanField(default=False)
    img_name = models.CharField(max_length=255)
    image_url = models.URLField()
    username = None

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
