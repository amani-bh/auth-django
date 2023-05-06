from django.db import models
from django.contrib.auth.models import AbstractUser


# Create your models here.

class User(AbstractUser):
    phone = models.CharField(max_length=15)
    email = models.CharField(max_length=255, unique=True)
    password = models.CharField(max_length=255)
    is_active = models.BooleanField(default=False)
    private = models.BooleanField(default=False)
    img_name = models.CharField(max_length=255, default="default_image.png")
    followers_number = models.PositiveIntegerField(default=0)
    image_url = models.URLField(default="https://firebasestorage.googleapis.com/v0/b/ska-capgemini.appspot.com/o/images%2Fprofil-icon.png?alt=media&token=c7b30569-abc2-429c-a102-121229e26aed")
    username = None

    NOVICE = 'Novice'
    RESPONDER = 'Responder'
    CONTRIBUTOR = 'Contributor'
    EXPERT = 'Expert'
    BADGE_CHOICES = [
        (NOVICE, 'Novice'),
        (RESPONDER, 'Responder'),
        (CONTRIBUTOR, 'Contributor'),
        (EXPERT, 'Expert'),
    ]
    badge = models.CharField(
        max_length=255,
        choices=BADGE_CHOICES,
        default=NOVICE,
    )
    followers = models.ManyToManyField(
        'self',
        related_name='following',
        symmetrical=False,
        blank=True,
        null=True
    )

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
