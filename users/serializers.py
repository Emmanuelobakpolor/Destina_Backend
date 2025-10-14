from rest_framework import serializers
from .models import User, DriverProfile, Vehicle, Document

class UserSerializer(serializers.ModelSerializer):
    display_name = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['id', 'email', 'role', 'full_name', 'phone_number', 'date_of_birth', 'display_name']

    def get_display_name(self, obj):
        if obj.role == 'driver':
            try:
                return obj.driver_profile.first_name or 'Driver'
            except DriverProfile.DoesNotExist:
                return 'Driver'
        else:
            return obj.full_name or 'User'

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

class DocumentSerializer(serializers.ModelSerializer):
    user_email = serializers.CharField(source='user.email', read_only=True)

    class Meta:
        model = Document
        fields = ['user_email', 'file_url', 'file_type', 'uploaded_at']
        read_only_fields = ['user_email', 'uploaded_at']

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

# REMOVE THESE DUPLICATE/UNNECESSARY SERIALIZERS:
# - DriverSignupSerializer (duplicate functionality)
# - InitiateDriverSignupWithFilesSerializer (we're removing the initiate endpoint)
# - VerifyDriverSignupSerializer (we're using VerifyDriverSignupWithFilesSerializer instead)

class DriverProfileUpdateSerializer(serializers.Serializer):
    city = serializers.CharField(max_length=100)
    service_type = serializers.CharField(max_length=100)
    first_name = serializers.CharField(max_length=100)
    last_name = serializers.CharField(max_length=100)
    license_number = serializers.CharField(max_length=50)
    license_expiry = serializers.DateField()
    referral_code = serializers.CharField(max_length=50, required=False, allow_blank=True)
    license_document = serializers.URLField(required=False)
    selfie = serializers.URLField(required=False)

class VehicleUpdateSerializer(serializers.Serializer):
    brand = serializers.CharField(max_length=100)
    year = serializers.IntegerField()
    manufacturer = serializers.CharField(max_length=100)
    color = serializers.CharField(max_length=50)
    plate_number = serializers.CharField(max_length=20)
    road_worthiness = serializers.URLField(required=False)
    insurance_certificate = serializers.URLField(required=False)
    front_image = serializers.URLField(required=False)
    back_image = serializers.URLField(required=False)
    inside_image = serializers.URLField(required=False)

class UserProfileUpdateSerializer(serializers.Serializer):
    full_name = serializers.CharField(max_length=255, required=False, allow_blank=True)
    phone_number = serializers.CharField(max_length=15, required=False, allow_blank=True)
    date_of_birth = serializers.DateField(required=False)

# KEEP ONLY THIS ONE FOR DRIVER SIGNUP - IT HANDLES EVERYTHING:
class VerifyDriverSignupWithFilesSerializer(serializers.Serializer):
    # Verification
    email = serializers.EmailField()
    code = serializers.CharField(max_length=6)
    role = serializers.ChoiceField(choices=User.ROLE_CHOICES)

    # Personal Information
    first_name = serializers.CharField(max_length=100, required=False, allow_blank=True)
    last_name = serializers.CharField(max_length=100, required=False, allow_blank=True)
    license_number = serializers.CharField(max_length=50, required=False, allow_blank=True)
    license_expiry = serializers.DateField(required=False)
    phone_number = serializers.CharField(max_length=15, required=False, allow_blank=True)
    referral_code = serializers.CharField(max_length=50, required=False, allow_blank=True)

    # Service Details
    city = serializers.CharField(max_length=100, required=False, allow_blank=True)
    service_type = serializers.CharField(max_length=100, required=False, allow_blank=True)

    # Vehicle Information
    brand = serializers.CharField(max_length=100, required=False, allow_blank=True)
    year = serializers.IntegerField(required=False)
    manufacturer = serializers.CharField(max_length=100, required=False, allow_blank=True)
    color = serializers.CharField(max_length=50, required=False, allow_blank=True)
    plate_number = serializers.CharField(max_length=20, required=False, allow_blank=True)

    # File uploads
    license_document = serializers.FileField(required=False)
    selfie = serializers.FileField(required=False)
    road_worthiness = serializers.FileField(required=False)
    insurance_certificate = serializers.FileField(required=False)
    front_image = serializers.FileField(required=False)
    back_image = serializers.FileField(required=False)
    inside_image = serializers.FileField(required=False)

    def validate(self, data):
        # You can add custom validation logic here if needed
        # e.g., ensure license_document is PDF, selfie is image, etc.
        return data