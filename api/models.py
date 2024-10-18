from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission
import uuid
from django.core.validators import RegexValidator


class CustomUser(AbstractUser):
    username = models.CharField(max_length=150, unique=True, blank=True, null=True)
    email = models.EmailField(unique=True)
    # Additional fields
    avatar = models.ImageField(upload_to="avatars/", blank=True, null=True)
    phone_number = models.CharField(max_length=15, blank=True)
    is_verified = models.BooleanField(default=False)

    # Referral fields
    referral_code = models.CharField(max_length=10, unique=True, blank=True)
    referred_by = models.ForeignKey(
        "self",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="referrals",
    )

    # Override default related names to prevent clashes
    groups = models.ManyToManyField(
        Group,
        related_name="customuser_set",
        blank=True,
        help_text="The groups this user belongs to.",
    )
    user_permissions = models.ManyToManyField(
        Permission,
        related_name="customuser_set",
        blank=True,
        help_text="Specific permissions for this user.",
    )
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]
