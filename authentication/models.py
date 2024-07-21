from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from datetime import timedelta
import secrets


class UserManager(BaseUserManager):
    """Define a model manager for User model with no username field."""

    use_in_migrations = True

    def _create_user(self, email, password, **extra_fields):
        """Create and save a User with the given email and password."""
        if not email:
            raise ValueError('The given email must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        """Create and save a regular User with the given email and password."""
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password, **extra_fields):
        """Create and save a SuperUser with the given email and password."""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self._create_user(email, password, **extra_fields)


class User(AbstractUser):
    """User model."""
    username = None
    email = models.EmailField(_("Email Address"), unique=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = UserManager()


class OTP(models.Model):
    user_email = models.EmailField()
    otp_code = models.CharField(max_length=6)
    expiry_time = models.DateTimeField()

    @classmethod
    def create(self, user_email, validity_minutes=5):
        otp_code = secrets.token_hex(3)
        expiry_time = timezone.now() + timedelta(minutes=validity_minutes)
        otp, created = self.objects.update_or_create(user_email=user_email, defaults={'otp_code':otp_code, 'expiry_time':expiry_time})
        return otp

    @classmethod
    def verify(self, user_email, otp_code):
        try:
            otp = self.objects.get(user_email=user_email, otp_code=otp_code, expiry_time__gt=timezone.now())
            otp.delete()  # Delete OTP after successful verification
            return True
        except self.DoesNotExist:
            return False