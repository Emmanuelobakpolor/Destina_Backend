from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone
import json


class UserManager(BaseUserManager):
    def create_user(self, email, role, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email must be set')
        if not role:
            raise ValueError('User role must be set')
        user = self.model(email=email, role=role, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, role='admin', password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, role, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    ROLE_CHOICES = (
        ('driver', 'Driver'),
        ('user', 'User'),
        ('admin', 'Admin'),
    )

    email = models.EmailField(unique=True, null=True)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES)
    full_name = models.CharField(max_length=255, blank=True, null=True)
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    date_of_birth = models.DateField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['role']

    def __str__(self):
        return f"{self.email} ({self.role})"


class VerificationCode(models.Model):
    email = models.EmailField(null=True)
    code = models.CharField(max_length=6)
    type = models.CharField(max_length=10, choices=[('signup', 'Signup'), ('login', 'Login')])
    data = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        return timezone.now() > self.created_at + timezone.timedelta(minutes=20)

    class Meta:
        unique_together = ('email', 'type')

    def __str__(self):
        return f"VerificationCode for {self.email} ({self.type})"


class DriverProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='driver_profile')
    city = models.CharField(max_length=100, blank=True, null=True)
    service_type = models.CharField(max_length=100, blank=True, null=True)  # e.g., 'Instant & Schedule Ride'
    first_name = models.CharField(max_length=100, blank=True, null=True)
    last_name = models.CharField(max_length=100, blank=True, null=True)
    license_number = models.CharField(max_length=50, blank=True, null=True)
    license_expiry = models.DateField(blank=True, null=True)
    referral_code = models.CharField(max_length=50, blank=True, null=True)
    verification_status = models.CharField(
        max_length=10,
        choices=[('pending', 'Pending'), ('approved', 'Approved'), ('rejected', 'Rejected')],
        default='pending'
    )

    def __str__(self):
        return f"Driver Profile for {self.user.email}"


class Vehicle(models.Model):
    driver_profile = models.OneToOneField(DriverProfile, on_delete=models.CASCADE, related_name='vehicle')
    brand = models.CharField(max_length=100, blank=True, null=True)
    year = models.IntegerField(blank=True, null=True)
    manufacturer = models.CharField(max_length=100, blank=True, null=True)
    color = models.CharField(max_length=50, blank=True, null=True)
    plate_number = models.CharField(max_length=20, blank=True, null=True)

    def __str__(self):
        return f"Vehicle for {self.driver_profile.user.email}"


from .storage import CloudinaryStorage

class DriverDocument(models.Model):
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='driver_documents'
    )
    document_type = models.CharField(
        max_length=50,
        choices=[
            ('license_document', 'License Document'),
            ('selfie', 'Selfie'),
            ('road_worthiness', 'Road Worthiness'),
            ('insurance_certificate', 'Insurance Certificate'),
            ('front_image', 'Front Image'),
            ('back_image', 'Back Image'),
            ('inside_image', 'Inside Image'),
        ]
    )
    file = models.FileField(upload_to='driver_documents/%Y/%m/%d/', storage=CloudinaryStorage())
    uploaded_at = models.DateTimeField(auto_now_add=True)
    expiry_date = models.DateField(blank=True, null=True)  # For license/insurance

    class Meta:
        verbose_name = 'Driver Document'
        verbose_name_plural = 'Driver Documents'
        unique_together = ('user', 'document_type')  # Ensures one file per type per user

    def __str__(self):
        return f"{self.document_type} for {self.user.email}"
