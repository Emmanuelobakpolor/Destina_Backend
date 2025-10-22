from rest_framework import serializers
from .models import User, DriverProfile, Vehicle, VerificationCode, DriverDocument

class UserSerializer(serializers.ModelSerializer):
    display_name = serializers.SerializerMethodField()
    profile_picture = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['id', 'email', 'role', 'full_name', 'phone_number', 'date_of_birth', 'display_name', 'profile_picture']

    def get_profile_picture(self, obj):
        request = self.context.get('request')
        if obj.profile_picture and hasattr(obj.profile_picture, 'url'):
            return request.build_absolute_uri(obj.profile_picture.url)
        return None

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

class DriverProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = DriverProfile
        fields = ['id', 'user', 'city', 'service_type', 'first_name', 'last_name', 'license_number', 'license_expiry', 'referral_code', 'verification_status', 'wallet']
        read_only_fields = ['user']

class VehicleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vehicle
        fields = ['id', 'driver_profile', 'brand', 'year', 'manufacturer', 'color', 'plate_number']
        read_only_fields = ['driver_profile']

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
    profile_picture = serializers.ImageField(required=False)

# KEEP ONLY THIS ONE FOR DRIVER SIGNUP - IT HANDLES EVERYTHING:
class VerifyDriverSignupWithFilesSerializer(serializers.Serializer):
    email = serializers.EmailField()
    code = serializers.CharField(max_length=6)
    role = serializers.ChoiceField(choices=User.ROLE_CHOICES)
    first_name = serializers.CharField(max_length=100, required=False, allow_blank=True)
    last_name = serializers.CharField(max_length=100, required=False, allow_blank=True)
    license_number = serializers.CharField(max_length=50, required=False, allow_blank=True)
    license_expiry = serializers.DateField(required=False)
    phone_number = serializers.CharField(max_length=15, required=False, allow_blank=True)
    referral_code = serializers.CharField(max_length=50, required=False, allow_blank=True)
    city = serializers.CharField(max_length=100, required=False, allow_blank=True)
    service_type = serializers.CharField(max_length=100, required=False, allow_blank=True)
    brand = serializers.CharField(max_length=100, required=False, allow_blank=True)
    year = serializers.IntegerField(required=False)
    manufacturer = serializers.CharField(max_length=100, required=False, allow_blank=True)
    color = serializers.CharField(max_length=50, required=False, allow_blank=True)
    plate_number = serializers.CharField(max_length=20, required=False, allow_blank=True)
    license_document = serializers.FileField(required=False)
    selfie = serializers.ImageField(required=False)
    road_worthiness = serializers.FileField(required=False)
    insurance_certificate = serializers.FileField(required=False)
    front_image = serializers.ImageField(required=False)
    back_image = serializers.ImageField(required=False)
    inside_image = serializers.ImageField(required=False)

    def validate(self, data):
        email = data.get('email')
        code = data.get('code')
        try:
            verification = VerificationCode.objects.get(email=email, code=code, type='signup')
            if verification.is_expired():
                raise serializers.ValidationError("Verification code has expired")
        except VerificationCode.DoesNotExist:
            raise serializers.ValidationError("Invalid verification code")
        return data


class DriverDocumentSerializer(serializers.ModelSerializer):
    url = serializers.SerializerMethodField()

    class Meta:
        model = DriverDocument
        fields = ['id', 'document_type', 'uploaded_at', 'expiry_date', 'url']
        read_only_fields = ['id', 'uploaded_at', 'expiry_date', 'url']

    def get_url(self, obj):
        request = self.context.get('request')
        if obj.file and hasattr(obj.file, 'url'):
            return obj.file.url
        return None
