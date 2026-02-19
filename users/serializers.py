from rest_framework import serializers
from .models import User, DriverProfile, Vehicle, VerificationCode, DriverDocument, Route, Reservation, FlutterwaveSubaccount, WithdrawalRequest, Notification, UserNotification
from datetime import timedelta

class UserSerializer(serializers.ModelSerializer):
    display_name = serializers.SerializerMethodField()
    profile_picture = serializers.SerializerMethodField()
    has_subaccount = serializers.SerializerMethodField()
    subaccount_balance = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['id', 'email', 'role', 'full_name', 'phone_number', 'date_of_birth', 'display_name', 'profile_picture', 'wallet', 'todays_earnings', 'is_active', 'has_subaccount', 'subaccount_balance', 'last_location', 'created_at']

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

    def get_has_subaccount(self, obj):
        if obj.role == 'driver':
            try:
                return obj.driver_profile.flutterwave_subaccount is not None
            except (DriverProfile.DoesNotExist, FlutterwaveSubaccount.DoesNotExist):
                return False
        return False

    def get_subaccount_balance(self, obj):
        if obj.role == 'driver':
            try:
                subaccount = obj.driver_profile.flutterwave_subaccount
                if subaccount:
                    # Fetch balance from Flutterwave API (placeholder; implement in view)
                    return obj.driver_profile.wallet  # Fallback to wallet for now
            except (DriverProfile.DoesNotExist, FlutterwaveSubaccount.DoesNotExist):
                pass
        return obj.wallet

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
        fields = ['id', 'driver_profile', 'brand', 'year', 'color', 'plate_number']
        read_only_fields = ['driver_profile']

class DriverProfileUpdateSerializer(serializers.Serializer):
    city = serializers.CharField(max_length=100, required=False, allow_blank=True)
    service_type = serializers.CharField(max_length=100, required=False, allow_blank=True)
    first_name = serializers.CharField(max_length=100, required=False, allow_blank=True)
    last_name = serializers.CharField(max_length=100, required=False, allow_blank=True)
    license_number = serializers.CharField(max_length=50, required=False, allow_blank=True)
    license_expiry = serializers.DateField(required=False)
    referral_code = serializers.CharField(max_length=50, required=False, allow_blank=True)
    license_document = serializers.FileField(required=False)
    selfie = serializers.ImageField(required=False)

class VehicleUpdateSerializer(serializers.Serializer):
    brand = serializers.CharField(max_length=100)
    year = serializers.IntegerField()
    color = serializers.CharField(max_length=50)
    plate_number = serializers.CharField(max_length=20)
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
    color = serializers.CharField(max_length=50, required=False, allow_blank=True)
    plate_number = serializers.CharField(max_length=20, required=False, allow_blank=True)
    license_document = serializers.FileField(required=False)
    selfie = serializers.ImageField(required=False)
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


class RouteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Route
        fields = ['id', 'origin', 'destination', 'fare', 'date', 'time', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']

    def create(self, validated_data):
        user = self.context['request'].user
        profile = user.driver_profile
        validated_data['driver_profile'] = profile
        return super().create(validated_data)


class SearchRouteSerializer(serializers.ModelSerializer):
    name = serializers.SerializerMethodField()
    type = serializers.SerializerMethodField()
    price = serializers.SerializerMethodField()
    departureDate = serializers.DateField(source='date')
    departureTime = serializers.SerializerMethodField()
    departureLocation = serializers.SerializerMethodField()
    arrivalTime = serializers.SerializerMethodField()
    arrivalLocation = serializers.SerializerMethodField()
    duration = serializers.SerializerMethodField()
    capacity = serializers.SerializerMethodField()
    brand = serializers.SerializerMethodField()
    plate_number = serializers.SerializerMethodField()
    front_image_url = serializers.SerializerMethodField()
    phone_number = serializers.CharField(source='driver_profile.user.phone_number')
    selfie_url = serializers.SerializerMethodField()
    first_name = serializers.CharField(source='driver_profile.first_name')
    last_name = serializers.CharField(source='driver_profile.last_name')
    route_id = serializers.IntegerField(source='id')

    class Meta:
        model = Route
        fields = ['name', 'type', 'price', 'departureDate', 'departureTime', 'departureLocation', 'arrivalTime', 'arrivalLocation', 'duration', 'capacity', 'brand', 'plate_number', 'front_image_url', 'phone_number', 'selfie_url', 'first_name', 'last_name', 'route_id']

    def get_name(self, obj):
        profile = obj.driver_profile
        first_name = profile.first_name or ''
        last_name = profile.last_name or ''
        return f"{first_name} {last_name}".strip() or 'Driver'

    def get_type(self, obj):
        return obj.driver_profile.service_type or 'Ride Service'

    def get_price(self, obj):
        return float(obj.fare) if obj.fare else 0

    def get_departureTime(self, obj):
        return obj.time.strftime('%H:%M') if obj.time else None

    def get_departureLocation(self, obj):
        return obj.origin

    def get_arrivalTime(self, obj):
        return 'Destination'

    def get_arrivalLocation(self, obj):
        return obj.destination

    def get_duration(self, obj):
        return 'TBD'  # Default duration

    def get_capacity(self, obj):
        return 4  # Default capacity

    def get_brand(self, obj):
        try:
            return obj.driver_profile.vehicle.brand
        except Vehicle.DoesNotExist:
            return None

    def get_plate_number(self, obj):
        try:
            return obj.driver_profile.vehicle.plate_number
        except Vehicle.DoesNotExist:
            return None

    def get_front_image_url(self, obj):
        request = self.context.get('request')
        try:
            doc = DriverDocument.objects.get(user=obj.driver_profile.user, document_type='front_image')
            if doc.file and hasattr(doc.file, 'url'):
                return request.build_absolute_uri(doc.file.url)
        except DriverDocument.DoesNotExist:
            pass
        return None

    def get_selfie_url(self, obj):
        request = self.context.get('request')
        try:
            doc = DriverDocument.objects.get(user=obj.driver_profile.user, document_type='selfie')
            if doc.file and hasattr(doc.file, 'url'):
                return request.build_absolute_uri(doc.file.url)
        except DriverDocument.DoesNotExist:
            pass
        return None


class ReservationSerializer(serializers.ModelSerializer):
    time = serializers.TimeField(required=False, allow_null=True)
    user = UserSerializer(read_only=True)

    class Meta:
        model = Reservation
        fields = ['id', 'user', 'ride_type', 'status', 'pickup_location', 'destination', 'reservation_seats', 'amount', 'date', 'time', 'driver_name', 'driver_phone', 'driver_profile_image_url', 'driver_rating', 'driver_trips', 'vehicle_plate', 'vehicle_brand', 'driver_company', 'driver', 'route', 'tx_ref', 'payment_reference', 'created_at']
        read_only_fields = ['id', 'user', 'driver', 'route', 'created_at']


class FlutterwaveSubaccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = FlutterwaveSubaccount
        fields = ['id', 'driver_profile', 'subaccount_id', 'account_reference', 'account_name', 'account_number', 'bank_code', 'bank_name', 'created_at', 'updated_at']
        read_only_fields = ['id', 'driver_profile', 'subaccount_id', 'account_reference', 'created_at', 'updated_at']


class NotificationSerializer(serializers.ModelSerializer):
    reservation = ReservationSerializer(read_only=True)

    class Meta:
        model = Notification
        fields = ['id', 'driver_profile', 'message', 'type', 'is_read', 'created_at', 'reservation']
        read_only_fields = ['id', 'driver_profile', 'created_at']


class WithdrawalRequestSerializer(serializers.ModelSerializer):
    subaccount = serializers.SerializerMethodField()

    class Meta:
        model = WithdrawalRequest
        fields = ['id', 'driver_profile', 'amount', 'reason', 'status', 'requested_at', 'processed_at', 'notes', 'subaccount']
        read_only_fields = ['id', 'driver_profile', 'requested_at', 'processed_at', 'notes', 'subaccount']

    def get_subaccount(self, obj):
        try:
            subaccount = obj.driver_profile.flutterwave_subaccount
            return FlutterwaveSubaccountSerializer(subaccount).data
        except FlutterwaveSubaccount.DoesNotExist:
            return None


class DriverEarningsSerializer(serializers.ModelSerializer):
    display_name = serializers.SerializerMethodField()
    profile_picture = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['id', 'email', 'full_name', 'display_name', 'profile_picture', 'todays_earnings']

    def get_profile_picture(self, obj):
        request = self.context.get('request')
        if obj.profile_picture and hasattr(obj.profile_picture, 'url'):
            return request.build_absolute_uri(obj.profile_picture.url)
        return None

    def get_display_name(self, obj):
        if obj.role == 'driver':
            try:
                return obj.driver_profile.first_name or obj.full_name or 'Driver'
            except DriverProfile.DoesNotExist:
                return obj.full_name or 'Driver'
        return obj.full_name or 'User'


class TotalEarningsSerializer(serializers.Serializer):
    total_earnings = serializers.DecimalField(max_digits=10, decimal_places=2)


class UserNotificationSerializer(serializers.ModelSerializer):
    reservation = ReservationSerializer(read_only=True)

    class Meta:
        model = UserNotification
        fields = ['id', 'user', 'message', 'type', 'is_read', 'created_at', 'reservation']
        read_only_fields = ['id', 'user', 'created_at']
