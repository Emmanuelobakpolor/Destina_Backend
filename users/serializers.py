from rest_framework import serializers
from .models import User, DriverProfile, Vehicle

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'role', 'full_name', 'phone_number', 'date_of_birth']

class SignupSerializer(serializers.Serializer):
    email = serializers.EmailField()
    role = serializers.ChoiceField(choices=User.ROLE_CHOICES)
    full_name = serializers.CharField(max_length=255, required=False, allow_blank=True)
    phone_number = serializers.CharField(max_length=15, required=False, allow_blank=True)
    date_of_birth = serializers.DateField(required=False)

class VerifySignupSerializer(serializers.Serializer):
    email = serializers.EmailField()
    code = serializers.CharField(max_length=6)
    role = serializers.ChoiceField(choices=User.ROLE_CHOICES)

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()

class VerifyLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    code = serializers.CharField(max_length=6)

class DriverProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = DriverProfile
        fields = ['id', 'user', 'city', 'service_type', 'first_name', 'last_name', 'license_number', 'license_expiry', 'referral_code', 'verification_status', 'license_document', 'selfie']
        read_only_fields = ['user']

class VehicleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vehicle
        fields = ['id', 'driver_profile', 'brand', 'year', 'manufacturer', 'color', 'plate_number', 'road_worthiness', 'insurance_certificate', 'front_image', 'back_image', 'inside_image']
        read_only_fields = ['driver_profile']

class DriverSignupSerializer(serializers.Serializer):
    email = serializers.EmailField()
    phone_number = serializers.CharField(max_length=15, required=False, allow_blank=True)
    referral_code = serializers.CharField(max_length=50, required=False, allow_blank=True)

class DriverProfileUpdateSerializer(serializers.Serializer):
    city = serializers.CharField(max_length=100)
    service_type = serializers.CharField(max_length=100)
    first_name = serializers.CharField(max_length=100)
    last_name = serializers.CharField(max_length=100)
    license_number = serializers.CharField(max_length=50)
    license_expiry = serializers.DateField()
    referral_code = serializers.CharField(max_length=50, required=False, allow_blank=True)
    license_document = serializers.FileField(required=False)
    selfie = serializers.ImageField(required=False)

class VehicleUpdateSerializer(serializers.Serializer):
    brand = serializers.CharField(max_length=100)
    year = serializers.IntegerField()
    manufacturer = serializers.CharField(max_length=100)
    color = serializers.CharField(max_length=50)
    plate_number = serializers.CharField(max_length=20)
    road_worthiness = serializers.FileField(required=False)
    insurance_certificate = serializers.FileField(required=False)
    front_image = serializers.ImageField(required=False)
    back_image = serializers.ImageField(required=False)
    inside_image = serializers.ImageField(required=False)


class UserProfileUpdateSerializer(serializers.Serializer):
    full_name = serializers.CharField(max_length=255, required=False, allow_blank=True)
    phone_number = serializers.CharField(max_length=15, required=False, allow_blank=True)
    date_of_birth = serializers.DateField(required=False)


class VerifyDriverSignupSerializer(serializers.Serializer):
    email = serializers.EmailField()
    code = serializers.CharField(max_length=6)

class VerifyDriverSignupWithFilesSerializer(serializers.Serializer):
    email = serializers.EmailField()
    code = serializers.CharField(max_length=6)
    role = serializers.ChoiceField(choices=User.ROLE_CHOICES)
    # Personal
    first_name = serializers.CharField(max_length=100, required=False, allow_blank=True)
    last_name = serializers.CharField(max_length=100, required=False, allow_blank=True)
    license_number = serializers.CharField(max_length=50, required=False, allow_blank=True)
    license_expiry = serializers.DateField(required=False)
    license_document = serializers.FileField(required=False)
    selfie = serializers.ImageField(required=False)
    # Vehicle
    city = serializers.CharField(max_length=100, required=False, allow_blank=True)
    service_type = serializers.CharField(max_length=100, required=False, allow_blank=True)
    brand = serializers.CharField(max_length=100, required=False, allow_blank=True)
    year = serializers.IntegerField(required=False)
    manufacturer = serializers.CharField(max_length=100, required=False, allow_blank=True)
    color = serializers.CharField(max_length=50, required=False, allow_blank=True)
    plate_number = serializers.CharField(max_length=20, required=False, allow_blank=True)
    road_worthiness = serializers.FileField(required=False)
    insurance_certificate = serializers.FileField(required=False)
    front_image = serializers.ImageField(required=False)
    back_image = serializers.ImageField(required=False)
    inside_image = serializers.ImageField(required=False)
    # Basic
    phone_number = serializers.CharField(max_length=15, required=False, allow_blank=True)
    referral_code = serializers.CharField(max_length=50, required=False, allow_blank=True)

class InitiateDriverSignupWithFilesSerializer(serializers.Serializer):
    email = serializers.EmailField()
    # Personal
    first_name = serializers.CharField(max_length=100, required=False, allow_blank=True)
    last_name = serializers.CharField(max_length=100, required=False, allow_blank=True)
    license_number = serializers.CharField(max_length=50, required=False, allow_blank=True)
    license_expiry = serializers.DateField(required=False)
    license_document = serializers.FileField(required=False)
    selfie = serializers.ImageField(required=False)
    # Vehicle
    city = serializers.CharField(max_length=100, required=False, allow_blank=True)
    service_type = serializers.CharField(max_length=100, required=False, allow_blank=True)
    brand = serializers.CharField(max_length=100, required=False, allow_blank=True)
    year = serializers.IntegerField(required=False)
    manufacturer = serializers.CharField(max_length=100, required=False, allow_blank=True)
    color = serializers.CharField(max_length=50, required=False, allow_blank=True)
    plate_number = serializers.CharField(max_length=20, required=False, allow_blank=True)
    road_worthiness = serializers.FileField(required=False)
    insurance_certificate = serializers.FileField(required=False)
    front_image = serializers.ImageField(required=False)
    back_image = serializers.ImageField(required=False)
    inside_image = serializers.ImageField(required=False)
    # Basic
    phone_number = serializers.CharField(max_length=15, required=False, allow_blank=True)
    referral_code = serializers.CharField(max_length=50, required=False, allow_blank=True)
