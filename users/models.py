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
    profile_picture = models.ImageField(upload_to='user_profile_pictures/%Y/%m/%d/', blank=True, null=True)
    wallet = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    todays_earnings = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    last_location = models.JSONField(blank=True, null=True)  # Store {'latitude': float, 'longitude': float, 'timestamp': datetime}
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

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
    wallet = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)

    def __str__(self):
        return f"Driver Profile for {self.user.email}"


class Vehicle(models.Model):
    driver_profile = models.OneToOneField(DriverProfile, on_delete=models.CASCADE, related_name='vehicle')
    brand = models.CharField(max_length=100, blank=True, null=True)
    year = models.IntegerField(blank=True, null=True)
    color = models.CharField(max_length=50, blank=True, null=True)
    plate_number = models.CharField(max_length=20, blank=True, null=True)

    def __str__(self):
        return f"Vehicle for {self.driver_profile.user.email}"


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
            ('front_image', 'Front Image'),
            ('back_image', 'Back Image'),
            ('inside_image', 'Inside Image'),
        ]
    )
    file = models.FileField(upload_to='driver_documents/%Y/%m/%d/')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    expiry_date = models.DateField(blank=True, null=True)  # For license

    class Meta:
        verbose_name = 'Driver Document'
        verbose_name_plural = 'Driver Documents'
        unique_together = ('user', 'document_type')  # Ensures one file per type per user

    def __str__(self):
        return f"{self.document_type} for {self.user.email}"


class Route(models.Model):
    driver_profile = models.ForeignKey(DriverProfile, on_delete=models.CASCADE, related_name='routes')
    origin = models.CharField(max_length=255)
    destination = models.CharField(max_length=255)
    fare = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    date = models.DateField(blank=True, null=True)
    time = models.TimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Route from {self.origin} to {self.destination} by {self.driver_profile.user.email}"


class Reservation(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='reservations')
    ride_type = models.CharField(max_length=10, choices=[('bus', 'Bus'), ('vehicle', 'Vehicle')])
    status = models.CharField(max_length=10, choices=[('pending', 'Pending'), ('active', 'Active'), ('paid', 'Paid'), ('cancelled', 'Cancelled')], default='pending')
    pickup_location = models.CharField(max_length=255)
    destination = models.CharField(max_length=255)
    reservation_seats = models.CharField(max_length=255)  # e.g., '1B, 2C'
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    date = models.DateField()
    time = models.TimeField(blank=True, null=True)
    driver_name = models.CharField(max_length=255, blank=True, null=True)
    driver_phone = models.CharField(max_length=15, blank=True, null=True)
    driver_profile_image_url = models.URLField(blank=True, null=True)
    vehicle_plate = models.CharField(max_length=20, blank=True, null=True)
    vehicle_brand = models.CharField(max_length=100, blank=True, null=True)
    driver_rating = models.DecimalField(decimal_places=2, max_digits=3, blank=True, null=True)
    driver_trips = models.IntegerField(blank=True, null=True)
    driver_company = models.CharField(max_length=255, blank=True, null=True)
    driver = models.ForeignKey('DriverProfile', on_delete=models.SET_NULL, null=True, blank=True, related_name='reservations')
    route = models.ForeignKey(Route, on_delete=models.SET_NULL, null=True, blank=True)
    tx_ref = models.CharField(max_length=100, blank=True, null=True, unique=True) # Client-generated transaction reference
    payment_reference = models.CharField(max_length=100, blank=True, null=True, unique=True)  # For Flutterwave payment tracking
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Reservation for {self.user.email} on {self.date}"


class FlutterwaveSubaccount(models.Model):
    driver_profile = models.OneToOneField(DriverProfile, on_delete=models.CASCADE, related_name='flutterwave_subaccount')
    subaccount_id = models.CharField(max_length=100, blank=True, null=True)  # Flutterwave subaccount ID
    account_reference = models.CharField(max_length=100, blank=True, null=True)  # Unique reference for the subaccount
    account_name = models.CharField(max_length=255)  # Bank account name
    account_number = models.CharField(max_length=20)  # Bank account number
    bank_code = models.CharField(max_length=10)  # Bank code (e.g., 058 for GTBank)
    bank_name = models.CharField(max_length=255, blank=True, null=True)  # Bank name for display
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Subaccount for {self.driver_profile.user.email} - {self.account_reference}"


class Notification(models.Model):
    driver_profile = models.ForeignKey(DriverProfile, on_delete=models.CASCADE, related_name='notifications')
    message = models.TextField()
    type = models.CharField(max_length=20, choices=[('reservation', 'Reservation'), ('system', 'System')], default='reservation')
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    reservation = models.ForeignKey(Reservation, on_delete=models.SET_NULL, null=True, blank=True, related_name='driver_notifications')

    def __str__(self):
        return f"Notification for {self.driver_profile.user.email}: {self.message[:50]}"


class UserNotification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_notifications')
    message = models.TextField()
    type = models.CharField(max_length=20, choices=[('reservation', 'Reservation'), ('payment', 'Payment'), ('system', 'System')], default='reservation')
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    reservation = models.ForeignKey(Reservation, on_delete=models.SET_NULL, null=True, blank=True, related_name='user_notifications')

    def __str__(self):
        return f"Notification for {self.user.email}: {self.message[:50]}"


class WithdrawalRequest(models.Model):
    driver_profile = models.ForeignKey(DriverProfile, on_delete=models.CASCADE, related_name='withdrawal_requests')
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    reason = models.TextField(blank=True, null=True)
    status = models.CharField(
        max_length=20,
        choices=[('pending', 'Pending'), ('approved', 'Approved'), ('rejected', 'Rejected'), ('processed', 'Processed')],
        default='pending'
    )
    requested_at = models.DateTimeField(auto_now_add=True)
    processed_at = models.DateTimeField(blank=True, null=True)
    notes = models.TextField(blank=True, null=True)  # Admin notes

    def __str__(self):
        return f"Withdrawal {self.amount} for {self.driver_profile.user.email} - {self.status}"
