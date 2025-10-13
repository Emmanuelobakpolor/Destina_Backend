from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import get_user_model
from .serializers import SignupSerializer, VerifyDriverSignupWithFilesSerializer, VerifySignupSerializer, LoginSerializer, VerifyLoginSerializer, DriverSignupSerializer, DriverProfileUpdateSerializer, VehicleUpdateSerializer, UserProfileUpdateSerializer, InitiateDriverSignupWithFilesSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
import random
from .models import DriverProfile, Vehicle, VerificationCode
import requests
from django.conf import settings
from django.utils import timezone
from datetime import date

User = get_user_model()

def send_email(email, message, retries=3):
    from django.core.mail import send_mail
    subject = "Verification Code"
    for attempt in range(retries):
        try:
            send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [email])
            return True, None  # Success
        except Exception as e:
            print(f"Email sending failed (attempt {attempt + 1}): {str(e)}")
            if attempt == retries - 1:
                return False, str(e)  # Failure after retries

    return False, "Unknown error"

# def send_sms(phone_number, message, retries=3):
#     sender = settings.TERMII_SENDER_ID if settings.TERMII_SENDER_ID_STATUS == "APPROVED" else "generic"  # Updated fallback

#     url = "https://v3.api.termii.com/api/sms/send"
#     payload = {
#         "to": phone_number,
#         "from": sender,
#         "sms": message,
#         "type": "plain",
#         "api_key": settings.TERMII_API_KEY,
#         "channel": "generic"
#     }

#     for attempt in range(retries):
#         try:
#             response = requests.post(url, json=payload)
#             response.raise_for_status()
#             return True, None  # Success
#         except Exception as e:
#             print(f"SMS sending failed (attempt {attempt + 1}): {response.text if 'response' in locals() else str(e)}")
#             if attempt == retries - 1:
#                 return False, str(e)  # Failure after retries

#     return False, "Unknown error"


class InitiateSignupView(APIView):
    def post(self, request):
        serializer = SignupSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            role = serializer.validated_data['role']
            # Generate verification code
            code = str(random.randint(100000, 999999))
            VerificationCode.objects.update_or_create(
                email=email,
                type='signup',
                defaults={
                    'code': code,
                    'data': {
                        'role': role,
                        'full_name': serializer.validated_data.get('full_name'),
                        'phone_number': serializer.validated_data.get('phone_number'),
                        'date_of_birth': serializer.validated_data.get('date_of_birth').isoformat() if serializer.validated_data.get('date_of_birth') else None,
                    },
                    'created_at': timezone.now()
                }
            )
            success, error_msg = send_email(email, f"Welcome to Destina, use the code {code} to complete verification")
            if not success:
                VerificationCode.objects.filter(email=email, type='signup').delete()  # Clean up
                return Response({"error": f"Failed to send email: {error_msg}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return Response({"message": "Verification code sent"}, status=status.HTTP_200_OK)
        print("Serializer errors:", serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class VerifySignupView(APIView):
    def post(self, request):
        serializer = VerifySignupSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            code = serializer.validated_data['code']
            role = serializer.validated_data['role']
            try:
                verification = VerificationCode.objects.get(email=email, type='signup')
            except VerificationCode.DoesNotExist:
                return Response({"error": "Verification code not found"}, status=status.HTTP_400_BAD_REQUEST)

            if verification.is_expired():
                verification.delete()
                return Response({"error": "Verification code expired"}, status=status.HTTP_400_BAD_REQUEST)

            if verification.code == code and verification.data.get('role') == role:
                user, created = User.objects.get_or_create(email=email, defaults={'role': role})
                if not created and user.role != role:
                    return Response({"error": "Role mismatch"}, status=status.HTTP_400_BAD_REQUEST)
                if verification.data.get('full_name'):
                    user.full_name = verification.data['full_name']
                if verification.data.get('phone_number'):
                    user.phone_number = verification.data['phone_number']
                if verification.data.get('date_of_birth'):
                    user.date_of_birth = date.fromisoformat(verification.data['date_of_birth'])
                user.save()
                verification.delete()
                refresh = RefreshToken.for_user(user)
                return Response({
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                    "message": "Signup verified"
                }, status=status.HTTP_200_OK)
            return Response({"error": "Invalid verification code"}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            if User.objects.filter(email=email).exists():
                code = str(random.randint(100000, 999999))
                VerificationCode.objects.update_or_create(
                    email=email,
                    type='login',
                    defaults={
                        'code': code,
                        'created_at': timezone.now()
                    }
                )
                success, error_msg = send_email(email, f"Welcome back {email}, your verification code is {code}")
                if not success:
                    VerificationCode.objects.filter(email=email, type='login').delete()  # Clean up
                    return Response({"error": f"Failed to send email: {error_msg}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                return Response({"message": "Login verification code sent"}, status=status.HTTP_200_OK)
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class VerifyLoginView(APIView):
    def post(self, request):
        serializer = VerifyLoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            code = serializer.validated_data['code']
            try:
                verification = VerificationCode.objects.get(email=email, type='login')
            except VerificationCode.DoesNotExist:
                return Response({"error": "Verification code not found"}, status=status.HTTP_400_BAD_REQUEST)

            if verification.is_expired():
                verification.delete()
                return Response({"error": "Verification code expired"}, status=status.HTTP_400_BAD_REQUEST)

            if verification.code == code:
                user = User.objects.filter(email=email).first()
                if user:
                    verification.delete()
                    refresh = RefreshToken.for_user(user)
                    response_data = {
                        "refresh": str(refresh),
                        "access": str(refresh.access_token),
                        "user": {
                            "id": user.id,
                            "email": user.email,
                            "role": user.role,
                            "full_name": user.full_name,
                            "phone_number": user.phone_number,
                        },
                        "message": "Login verified"
                    }
                    if user.role == 'driver':
                        try:
                            profile = user.driver_profile
                            response_data["user"]["verification_status"] = profile.verification_status
                            response_data["user"]["first_name"] = profile.first_name
                        except DriverProfile.DoesNotExist:
                            response_data["user"]["verification_status"] = None
                            response_data["user"]["first_name"] = None
                    return Response(response_data, status=status.HTTP_200_OK)
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            return Response({"error": "Invalid verification code"}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class InitiateDriverSignupView(APIView):
    def post(self, request):
        serializer = InitiateDriverSignupWithFilesSerializer(data=request.data)
        if serializer.is_valid():
            print("Validated data:", serializer.validated_data)
            email = serializer.validated_data['email']
            # Create user if not exists
            user, created = User.objects.get_or_create(email=email, defaults={'role': 'driver'})
            if not created and user.role != 'driver':
                return Response({"error": "Role mismatch"}, status=status.HTTP_400_BAD_REQUEST)

            # Update user with phone
            if serializer.validated_data.get('phone_number'):
                user.phone_number = serializer.validated_data['phone_number']
            user.save()

            # Create/update profile with personal data
            profile, created = DriverProfile.objects.get_or_create(user=user)
            profile.first_name = serializer.validated_data.get('first_name') or profile.first_name
            profile.last_name = serializer.validated_data.get('last_name') or profile.last_name
            profile.license_number = serializer.validated_data.get('license_number') or profile.license_number
            profile.license_expiry = serializer.validated_data.get('license_expiry') or profile.license_expiry
            profile.city = serializer.validated_data.get('city') or profile.city
            profile.service_type = serializer.validated_data.get('service_type') or profile.service_type
            profile.referral_code = serializer.validated_data.get('referral_code') or profile.referral_code
            if serializer.validated_data.get('license_document'):
                profile.license_document = serializer.validated_data['license_document']
            if serializer.validated_data.get('selfie'):
                profile.selfie = serializer.validated_data['selfie']
            profile.save()
            print("Profile saved:", profile.first_name, profile.last_name, profile.license_document, profile.selfie)

            # Create/update vehicle with vehicle data
            vehicle, created = Vehicle.objects.get_or_create(driver_profile=profile)
            vehicle.brand = serializer.validated_data.get('brand') or vehicle.brand
            vehicle.year = serializer.validated_data.get('year') or vehicle.year
            vehicle.manufacturer = serializer.validated_data.get('manufacturer') or vehicle.manufacturer
            vehicle.color = serializer.validated_data.get('color') or vehicle.color
            vehicle.plate_number = serializer.validated_data.get('plate_number') or vehicle.plate_number
            if serializer.validated_data.get('road_worthiness'):
                vehicle.road_worthiness = serializer.validated_data['road_worthiness']
            if serializer.validated_data.get('insurance_certificate'):
                vehicle.insurance_certificate = serializer.validated_data['insurance_certificate']
            if serializer.validated_data.get('front_image'):
                vehicle.front_image = serializer.validated_data['front_image']
            if serializer.validated_data.get('back_image'):
                vehicle.back_image = serializer.validated_data['back_image']
            if serializer.validated_data.get('inside_image'):
                vehicle.inside_image = serializer.validated_data['inside_image']
            vehicle.save()
            print("Vehicle saved:", vehicle.brand, vehicle.year, vehicle.manufacturer, vehicle.color, vehicle.plate_number, vehicle.front_image, vehicle.back_image, vehicle.inside_image)

            # Generate verification code
            code = str(random.randint(100000, 999999))
            VerificationCode.objects.update_or_create(
                email=email,
                type='signup',
                defaults={
                    'code': code,
                    'data': {'role': 'driver'},
                    'created_at': timezone.now()
                }
            )
            success, error_msg = send_email(email, f"Welcome to Destina, use the code {code} to complete verification")
            if not success:
                VerificationCode.objects.filter(email=email, type='signup').delete()  # Clean up
                return Response({"error": f"Failed to send email: {error_msg}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return Response({"message": "Verification code sent"}, status=status.HTTP_200_OK)
        print("Serializer errors:", serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class VerifyDriverSignupView(APIView):
    def post(self, request):
        serializer = VerifySignupSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            code = serializer.validated_data['code']
            role = serializer.validated_data['role']
            try:
                verification = VerificationCode.objects.get(email=email, type='signup')
            except VerificationCode.DoesNotExist:
                return Response({"error": "Verification code not found"}, status=status.HTTP_400_BAD_REQUEST)

            if verification.is_expired():
                verification.delete()
                return Response({"error": "Verification code expired"}, status=status.HTTP_400_BAD_REQUEST)

            if verification.code == code and verification.data.get('role') == role:
                user = User.objects.filter(email=email).first()
                if user:
                    profile = DriverProfile.objects.get(user=user)
                    profile.verification_status = 'pending'
                    profile.save()
                    verification.delete()
                    refresh = RefreshToken.for_user(user)
                    return Response({
                        "refresh": str(refresh),
                        "access": str(refresh.access_token),
                        "message": "Driver signup verified"
                    }, status=status.HTTP_200_OK)
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            return Response({"error": "Invalid verification code"}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class VerifyDriverSignupWithFilesView(APIView):
    def post(self, request):
        serializer = VerifyDriverSignupWithFilesSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            code = serializer.validated_data['code']
            role = serializer.validated_data['role']
            try:
                verification = VerificationCode.objects.get(email=email, type='signup')
            except VerificationCode.DoesNotExist:
                return Response({"error": "Verification code not found"}, status=status.HTTP_400_BAD_REQUEST)

            if verification.is_expired():
                verification.delete()
                return Response({"error": "Verification code expired"}, status=status.HTTP_400_BAD_REQUEST)

            if verification.code == code and verification.data.get('role') == role:
                user, created = User.objects.get_or_create(email=email, defaults={'role': role})
                if not created and user.role != role:
                    return Response({"error": "Role mismatch"}, status=status.HTTP_400_BAD_REQUEST)
                # Update user with phone
                if serializer.validated_data.get('phone_number'):
                    user.phone_number = serializer.validated_data['phone_number']
                user.save()

                # Create/update profile with personal data
                profile, created = DriverProfile.objects.get_or_create(user=user)
                profile.verification_status = 'pending'
                profile.first_name = serializer.validated_data.get('first_name') or profile.first_name
                profile.last_name = serializer.validated_data.get('last_name') or profile.last_name
                profile.license_number = serializer.validated_data.get('license_number') or profile.license_number
                profile.license_expiry = serializer.validated_data.get('license_expiry') or profile.license_expiry
                profile.city = serializer.validated_data.get('city') or profile.city
                profile.service_type = serializer.validated_data.get('service_type') or profile.service_type
                profile.referral_code = serializer.validated_data.get('referral_code') or profile.referral_code
                if serializer.validated_data.get('license_document'):
                    profile.license_document = serializer.validated_data['license_document']
                if serializer.validated_data.get('selfie'):
                    profile.selfie = serializer.validated_data['selfie']
                profile.save()

                # Create/update vehicle with vehicle data
                vehicle, created = Vehicle.objects.get_or_create(driver_profile=profile)
                vehicle.brand = serializer.validated_data.get('brand') or vehicle.brand
                vehicle.year = serializer.validated_data.get('year') or vehicle.year
                vehicle.manufacturer = serializer.validated_data.get('manufacturer') or vehicle.manufacturer
                vehicle.color = serializer.validated_data.get('color') or vehicle.color
                vehicle.plate_number = serializer.validated_data.get('plate_number') or vehicle.plate_number
                if serializer.validated_data.get('road_worthiness'):
                    vehicle.road_worthiness = serializer.validated_data['road_worthiness']
                if serializer.validated_data.get('insurance_certificate'):
                    vehicle.insurance_certificate = serializer.validated_data['insurance_certificate']
                if serializer.validated_data.get('front_image'):
                    vehicle.front_image = serializer.validated_data['front_image']
                if serializer.validated_data.get('back_image'):
                    vehicle.back_image = serializer.validated_data['back_image']
                if serializer.validated_data.get('inside_image'):
                    vehicle.inside_image = serializer.validated_data['inside_image']
                vehicle.save()

                verification.delete()
                refresh = RefreshToken.for_user(user)
                return Response({
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                    "user": {
                        "first_name": profile.first_name,
                    },
                    "message": "Driver signup verified with data"
                }, status=status.HTTP_200_OK)
            return Response({"error": "Invalid verification code"}, status=status.HTTP_400_BAD_REQUEST)
        print("Serializer errors:", serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ResendOTPView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)  # Reuse for email
        if serializer.is_valid():
            email = serializer.validated_data['email']
            type = request.data.get('type', 'signup')  # default to signup
            # Map driver-signup to signup since they use the same verification type
            if type == 'driver-signup':
                type = 'signup'
            if type not in ['signup', 'login']:
                return Response({"error": "Invalid type"}, status=status.HTTP_400_BAD_REQUEST)

            try:
                verification = VerificationCode.objects.get(email=email, type=type)
            except VerificationCode.DoesNotExist:
                return Response({"error": "Verification code not found"}, status=status.HTTP_400_BAD_REQUEST)

            if verification.is_expired():
                verification.delete()
                return Response({"error": "Verification code expired"}, status=status.HTTP_400_BAD_REQUEST)

            success, error_msg = send_email(email, f"Your verification code is {verification.code}")
            if not success:
                return Response({"error": f"Failed to resend email: {error_msg}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return Response({"message": "Verification code resent"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UpdateDriverProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        if user.role != 'driver':
            return Response({"error": "Only drivers can update profile"}, status=status.HTTP_403_FORBIDDEN)

        serializer = DriverProfileUpdateSerializer(data=request.data)
        if serializer.is_valid():
            profile, created = DriverProfile.objects.get_or_create(user=user)
            for attr, value in serializer.validated_data.items():
                setattr(profile, attr, value)
            profile.save()
            return Response({"message": "Driver profile updated"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UpdateVehicleView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        if user.role != 'driver':
            return Response({"error": "Only drivers can update vehicle"}, status=status.HTTP_403_FORBIDDEN)

        try:
            profile = user.driver_profile
        except DriverProfile.DoesNotExist:
            return Response({"error": "Driver profile not found"}, status=status.HTTP_404_NOT_FOUND)

        serializer = VehicleUpdateSerializer(data=request.data)
        if serializer.is_valid():
            vehicle, created = Vehicle.objects.get_or_create(driver_profile=profile)
            for attr, value in serializer.validated_data.items():
                setattr(vehicle, attr, value)
            vehicle.save()
            return Response({"message": "Vehicle updated"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UpdateUserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        serializer = UserProfileUpdateSerializer(data=request.data)
        if serializer.is_valid():
            for attr, value in serializer.validated_data.items():
                if value is not None:  # Only update if provided
                    setattr(user, attr, value)
            user.save()
            return Response({"message": "User profile updated"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class DriverVerificationStatusView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        if user.role != 'driver':
            return Response({"error": "Only drivers can check verification status"}, status=status.HTTP_403_FORBIDDEN)

        try:
            profile = user.driver_profile
            return Response({
                "verification_status": profile.verification_status
            }, status=status.HTTP_200_OK)
        except DriverProfile.DoesNotExist:
            return Response({"error": "Driver profile not found"}, status=status.HTTP_404_NOT_FOUND)

    def post(self, request):
        # For admin to update status
        user = request.user
        if user.role != 'admin':
            return Response({"error": "Only admins can update verification status"}, status=status.HTTP_403_FORBIDDEN)

        driver_id = request.data.get('driver_id')
        new_status = request.data.get('status')
        if not driver_id or new_status not in ['pending', 'approved', 'rejected']:
            return Response({"error": "Invalid data"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            profile = DriverProfile.objects.get(id=driver_id)
            profile.verification_status = new_status
            profile.save()
            return Response({"message": "Verification status updated"}, status=status.HTTP_200_OK)
        except DriverProfile.DoesNotExist:
            return Response({"error": "Driver profile not found"}, status=status.HTTP_404_NOT_FOUND)
