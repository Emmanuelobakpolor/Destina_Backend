from decimal import Decimal
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import get_user_model
from .serializers import DriverDocumentSerializer, SignupSerializer, VerifyDriverSignupWithFilesSerializer, VerifySignupSerializer, LoginSerializer, VerifyLoginSerializer, DriverProfileUpdateSerializer, VehicleUpdateSerializer, UserProfileUpdateSerializer, UserSerializer, RouteSerializer, ReservationSerializer, SearchRouteSerializer, FlutterwaveSubaccountSerializer, WithdrawalRequestSerializer, NotificationSerializer, DriverEarningsSerializer, TotalEarningsSerializer, UserNotificationSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.db.models import Sum
import random
from .models import DriverProfile, UserNotification, Vehicle, VerificationCode, DriverDocument, Route, Reservation, FlutterwaveSubaccount, WithdrawalRequest, Notification
from rest_framework.generics import ListCreateAPIView, RetrieveUpdateDestroyAPIView
import requests
from django.conf import settings
from django.utils import timezone
from datetime import date
import logging
import json
from django.db import transaction
from .utils import verify_flutterwave_webhook_signature
from django.shortcuts import render


from users import serializers


User = get_user_model()

# Set up logger for backend errors
logger = logging.getLogger(__name__)

# Helper function to create standardized error responses
def create_error_response(error_type, technical_details=None, status_code=status.HTTP_400_BAD_REQUEST):
    """
    Create a standardized error response.
    Logs technical details for debugging while returning user-friendly messages.
    """
    user_friendly_messages = {
        'email_send_failed': 'Unable to send verification email. Please try again later.',
        'invalid_email': 'Please enter a valid email address.',
        'user_not_found': 'No account found with this email address.',
        'verification_code_expired': 'Verification code has expired. Please request a new one.',
        'verification_code_not_found': 'Verification code not found. Please request a new one.',
        'invalid_verification_code': 'Invalid verification code. Please check and try again.',
        'role_mismatch': 'Account type mismatch. Please check your selection.',
        'server_error': 'Something went wrong on our end. Please try again later.',
        'network_error': 'Network connection issue. Please check your internet and try again.',
        'permission_denied': 'You do not have permission to perform this action.',
        'profile_not_found': 'Profile information not found.',
        'invalid_data': 'Please check your input and try again.',
        'duplicate_entry': 'This information is already registered.',
        'file_upload_error': 'File upload failed. Please try again.',
        'reservation_not_found': 'Reservation not found for this transaction. Please contact support.',
        'unknown_error': 'An unexpected error occurred. Please try again.',
    }

    user_message = user_friendly_messages.get(error_type, user_friendly_messages['unknown_error'])

    # Log technical details for debugging
    if technical_details:
        logger.error(f"Error type: {error_type}, Details: {technical_details}")
    else:
        logger.error(f"Error type: {error_type}")

    return Response({"error": user_message}, status=status_code)

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

class InitiateSignupView(APIView):
    def post(self, request):
        serializer = SignupSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            role = serializer.validated_data['role']
            # Check if email already exists
            if User.objects.filter(email=email).exists():
                return Response({"error": "Email already registered"}, status=status.HTTP_400_BAD_REQUEST)
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
                return create_error_response('email_send_failed', error_msg, status.HTTP_500_INTERNAL_SERVER_ERROR)
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
                    "user": {
                        "id": user.id,
                        "email": user.email,
                        "role": user.role,
                        "full_name": user.full_name,
                        "phone_number": user.phone_number,
                    },
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
                if settings.BYPASS_OTP:
                    code = "123456"
                else:
                    code = str(random.randint(100000, 999999))
                VerificationCode.objects.update_or_create(
                    email=email,
                    type='login',
                    defaults={
                        'code': code,
                        'created_at': timezone.now()
                    }
                )
                if not settings.BYPASS_OTP:
                    success, error_msg = send_email(email, f"Welcome back {email}, your verification code is {code}")
                    if not success:
                        VerificationCode.objects.filter(email=email, type='login').delete()  # Clean up
                        return create_error_response('email_send_failed', error_msg, status.HTTP_500_INTERNAL_SERVER_ERROR)
                return Response({"message": "Login verification code sent"}, status=status.HTTP_200_OK)
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class VerifyLoginView(APIView):
    def post(self, request):
        serializer = VerifyLoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            code = serializer.validated_data['code']
            if settings.BYPASS_OTP and email == 'lexisdevelopmentltd@gmail.com':
                # Skip OTP entirely for this email in bypass mode
                user = User.objects.filter(email=email).first()
                if user:
                    refresh = RefreshToken.for_user(user)
                    response_data = {
                        "refresh": str(refresh),
                        "access": str(refresh.access_token),
                        "user": { # This structure should be consistent
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
                            # Find the selfie document
                            selfie_doc = DriverDocument.objects.filter(user=user, document_type='selfie').first()
                            selfie_url = None
                            if selfie_doc and hasattr(selfie_doc.file, 'url'):
                                # Construct absolute URL if it's not already
                                request_obj = self.request
                                selfie_url = request_obj.build_absolute_uri(selfie_doc.file.url)

                            response_data["user"]["verification_status"] = profile.verification_status
                            response_data["user"]["first_name"] = profile.first_name
                            response_data["user"]["selfie_url"] = selfie_url
                        except DriverProfile.DoesNotExist: # Handle case where profile doesn't exist yet
                            response_data["user"]["verification_status"] = 'pending' # Assume pending if no profile
                            response_data["user"]["first_name"] = 'Driver' # Default name
                            response_data["user"]["selfie_url"] = None

                    # Add profile picture URL for all users
                    profile_picture_url = None
                    if user.profile_picture and hasattr(user.profile_picture, 'url'):
                        profile_picture_url = request.build_absolute_uri(user.profile_picture.url)
                    response_data["user"]["profile_picture"] = profile_picture_url

                    return Response(response_data, status=status.HTTP_200_OK)
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            elif settings.BYPASS_OTP:
                if code == "123456":
                    user = User.objects.filter(email=email).first()
                    if user:
                        # No need to delete verification as it's bypassed
                        refresh = RefreshToken.for_user(user)
                        response_data = {
                            "refresh": str(refresh),
                            "access": str(refresh.access_token),
                            "user": { # This structure should be consistent
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
                                # Find the selfie document
                                selfie_doc = DriverDocument.objects.filter(user=user, document_type='selfie').first()
                                selfie_url = None
                                if selfie_doc and hasattr(selfie_doc.file, 'url'):
                                    # Construct absolute URL if it's not already
                                    request_obj = self.request
                                    selfie_url = request_obj.build_absolute_uri(selfie_doc.file.url)

                                response_data["user"]["verification_status"] = profile.verification_status
                                response_data["user"]["first_name"] = profile.first_name
                                response_data["user"]["selfie_url"] = selfie_url
                            except DriverProfile.DoesNotExist: # Handle case where profile doesn't exist yet
                                response_data["user"]["verification_status"] = 'pending' # Assume pending if no profile
                                response_data["user"]["first_name"] = 'Driver' # Default name
                                response_data["user"]["selfie_url"] = None

                        # Add profile picture URL for all users
                        profile_picture_url = None
                        if user.profile_picture and hasattr(user.profile_picture, 'url'):
                            profile_picture_url = request.build_absolute_uri(user.profile_picture.url)
                        response_data["user"]["profile_picture"] = profile_picture_url

                        return Response(response_data, status=status.HTTP_200_OK)
                    return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
                return Response({"error": "Invalid verification code"}, status=status.HTTP_400_BAD_REQUEST)
            else:
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
                            "user": { # This structure should be consistent
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
                                # Find the selfie document
                                selfie_doc = DriverDocument.objects.filter(user=user, document_type='selfie').first()
                                selfie_url = None
                                if selfie_doc and hasattr(selfie_doc.file, 'url'):
                                    # Construct absolute URL if it's not already
                                    request_obj = self.request
                                    selfie_url = request_obj.build_absolute_uri(selfie_doc.file.url)

                                response_data["user"]["verification_status"] = profile.verification_status
                                response_data["user"]["first_name"] = profile.first_name
                                response_data["user"]["selfie_url"] = selfie_url
                            except DriverProfile.DoesNotExist: # Handle case where profile doesn't exist yet
                                response_data["user"]["verification_status"] = 'pending' # Assume pending if no profile
                                response_data["user"]["first_name"] = 'Driver' # Default name
                                response_data["user"]["selfie_url"] = None

                        # Add profile picture URL for all users
                        profile_picture_url = None
                        if user.profile_picture and hasattr(user.profile_picture, 'url'):
                            profile_picture_url = request.build_absolute_uri(user.profile_picture.url)
                        response_data["user"]["profile_picture"] = profile_picture_url

                        return Response(response_data, status=status.HTTP_200_OK)
                    return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
                return Response({"error": "Invalid verification code"}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class VerifyDriverSignupWithFilesView(APIView):
    def post(self, request):
        try:
            serializer = VerifyDriverSignupWithFilesSerializer(data=request.data)
            if serializer.is_valid():
                print("Validated data:", serializer.validated_data)
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
                    user, created = User.objects.get_or_create(
                        email=email,
                        defaults={'role': role}
                    )
                    if not created and user.role != role:
                        return Response({"error": "Role mismatch"}, status=status.HTTP_400_BAD_REQUEST)

                    if serializer.validated_data.get('phone_number'):
                        user.phone_number = serializer.validated_data['phone_number']
                    user.save()

                    profile, created = DriverProfile.objects.get_or_create(user=user)
                    profile.verification_status = 'pending'
                    profile_fields = [
                        'first_name', 'last_name', 'license_number', 'license_expiry',
                        'city', 'service_type', 'referral_code'
                    ]
                    for field in profile_fields:
                        if serializer.validated_data.get(field):
                            setattr(profile, field, serializer.validated_data[field])
                    profile.save()
                    print(f"Profile saved: {profile.first_name} {profile.last_name}")

                    vehicle, created = Vehicle.objects.get_or_create(driver_profile=profile)
                    vehicle_fields = ['brand', 'year', 'color', 'plate_number']
                    for field in vehicle_fields:
                        if serializer.validated_data.get(field):
                            setattr(vehicle, field, serializer.validated_data[field])
                    vehicle.save()
                    print(f"Vehicle saved: {vehicle.brand} {vehicle.plate_number}")

                    file_fields = [
                        ('license_document', serializer.validated_data.get('license_document'), serializer.validated_data.get('license_expiry')),
                        ('selfie', serializer.validated_data.get('selfie'), None),
                        ('front_image', serializer.validated_data.get('front_image'), None),
                        ('back_image', serializer.validated_data.get('back_image'), None),
                        ('inside_image', serializer.validated_data.get('inside_image'), None),
                    ]
                    for doc_type, file, expiry in file_fields:
                        if file:
                            DriverDocument.objects.update_or_create(
                                user=user,
                                document_type=doc_type,
                                defaults={'file': file, 'expiry_date': expiry}
                            )
                            print(f"Saved {doc_type} for {user.email}")

                    verification.delete()
                    refresh = RefreshToken.for_user(user)
                    return Response({
                        "refresh": str(refresh),
                        "access": str(refresh.access_token),
                        "user": {
                            "first_name": profile.first_name or 'Driver',
                            "email": user.email,
                            "role": user.role,
                            "verification_status": profile.verification_status
                        },
                        "message": "Driver signup completed successfully"
                    }, status=status.HTTP_200_OK)

                return Response({"error": "Invalid verification code"}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error in VerifyDriverSignupWithFilesView: {str(e)}")
            return create_error_response('server_error', str(e), status.HTTP_500_INTERNAL_SERVER_ERROR)


class ResendOTPView(APIView):
    def post(self, request):
        email = request.data.get('email')
        type = request.data.get('type', 'signup')  # default to signup
        # Map driver-signup to signup since they use the same verification type
        if type == 'driver-signup':
            type = 'signup'
        if type not in ['signup', 'login']:
            return Response({"error": "Invalid type"}, status=status.HTTP_400_BAD_REQUEST)

        if not email:
            return Response({"error": "Email is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            verification = VerificationCode.objects.get(email=email, type=type)
        except VerificationCode.DoesNotExist:
            return Response({"error": "Verification code not found"}, status=status.HTTP_400_BAD_REQUEST)

        if verification.is_expired():
            verification.delete()
            return Response({"error": "Verification code expired"}, status=status.HTTP_400_BAD_REQUEST)

        success, error_msg = send_email(email, f"Your verification code is {verification.code}")
        if not success:
            return create_error_response('email_send_failed', error_msg, status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response({"message": "Verification code resent"}, status=status.HTTP_200_OK)

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


class AllReservationsView(ListCreateAPIView):
    serializer_class = ReservationSerializer
    permission_classes = [AllowAny]

    def get_queryset(self):
        return Reservation.objects.filter(status='pending').order_by('-created_at')

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

class UploadUserProfilePictureView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        if 'profile_picture' not in request.FILES:
            return Response({"error": "No profile picture provided"}, status=status.HTTP_400_BAD_REQUEST)

        user.profile_picture = request.FILES['profile_picture']
        user.save()

        # Construct the absolute URL for the newly saved picture
        profile_picture_url = None
        if user.profile_picture and hasattr(user.profile_picture, 'url'):
            profile_picture_url = request.build_absolute_uri(user.profile_picture.url)

        return Response({"message": "Profile picture uploaded successfully", "profile_picture": profile_picture_url}, status=status.HTTP_200_OK)

class DriverVerificationStatusView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
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
        user_id = request.data.get('user_id')
        new_status = request.data.get('status')
        if not user_id or new_status not in ['pending', 'approved', 'rejected']:
            return Response({"error": "Invalid data"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            profile = DriverProfile.objects.get(user_id=user_id)
            profile.verification_status = new_status
            profile.save()
            return Response({"message": "Verification status updated"}, status=status.HTTP_200_OK)
        except DriverProfile.DoesNotExist:
            return Response({"error": "Driver profile not found"}, status=status.HTTP_404_NOT_FOUND)


class GetDriverVerificationStatusByIdView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, user_id):
        try:
            driver_user = User.objects.get(id=user_id, role='driver')
            profile = driver_user.driver_profile
            return Response({
                "verification_status": profile.verification_status
            }, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"error": "Driver not found"}, status=status.HTTP_404_NOT_FOUND)
        except DriverProfile.DoesNotExist:
            return Response({"error": "Driver profile not found"}, status=status.HTTP_404_NOT_FOUND)


class GetAdminDriverDocumentsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, user_id):
        user = request.user
        try:
            documents = DriverDocument.objects.filter(user_id=user_id).select_related('user')
            serializer = DriverDocumentSerializer(documents, many=True, context={'request': request})
            return Response({"documents": serializer.data}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class GetMyDriverDocumentsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        if user.role != 'driver':
            return Response({"error": "Only drivers can access their own documents"}, status=status.HTTP_403_FORBIDDEN)

        documents = DriverDocument.objects.filter(user=request.user)
        serializer = DriverDocumentSerializer(documents, many=True, context={'request': request})
        return Response({"documents": serializer.data}, status=status.HTTP_200_OK)


class UserStatsView(APIView):
    def get(self, request):
        total_users = User.objects.count()
        total_drivers = User.objects.filter(role='driver').count()
        total_regular_users = User.objects.filter(role='user').count()
        return Response({
            "total_users": total_users,
            "total_drivers": total_drivers,
            "total_regular_users": total_regular_users
        }, status=status.HTTP_200_OK)


class ListUsersView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        users = User.objects.filter(role='user')
        serializer = UserSerializer(users, many=True, context={'request': request})
        return Response({"users": serializer.data}, status=status.HTTP_200_OK)


class ListDriversView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        drivers = User.objects.filter(role='driver')
        serializer = UserSerializer(drivers, many=True, context={'request': request})
        return Response({"drivers": serializer.data}, status=status.HTTP_200_OK)


class GetDriverProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, user_id):
        user = request.user
        

        try:
            driver_user = User.objects.get(id=user_id, role='driver')
            profile = driver_user.driver_profile
            try:
                vehicle = profile.vehicle
            except Vehicle.DoesNotExist:
                vehicle = None

            # Get driver documents
            documents = DriverDocument.objects.filter(user=driver_user)
            document_serializer = DriverDocumentSerializer(documents, many=True, context={'request': request})

            profile_data = {
                "user_id": driver_user.id,
                "email": driver_user.email,
                "phone_number": driver_user.phone_number,
                "full_name": driver_user.full_name,
                "todays_earnings": float(driver_user.todays_earnings),
                "profile": {
                    "first_name": profile.first_name,
                    "last_name": profile.last_name,
                    "license_number": profile.license_number,
                    "license_expiry": profile.license_expiry,
                    "city": profile.city,
                    "service_type": profile.service_type,
                    "referral_code": profile.referral_code,
                    "verification_status": profile.verification_status,
                    "wallet": profile.wallet,
                },
                "vehicle": {
                    "brand": vehicle.brand if vehicle else None,
                    "year": vehicle.year if vehicle else None,
                    "color": vehicle.color if vehicle else None,
                    "plate_number": vehicle.plate_number if vehicle else None,
                } if vehicle else None,
                "documents": document_serializer.data
            }

            return Response(profile_data, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"error": "Driver not found"}, status=status.HTTP_404_NOT_FOUND)
        except DriverProfile.DoesNotExist:
            return Response({"error": "Driver profile not found"}, status=status.HTTP_404_NOT_FOUND)


class GetMyDriverProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        if user.role != 'driver':
            return Response({"error": "Only drivers can access their profile"}, status=status.HTTP_403_FORBIDDEN)

        try:
            profile = user.driver_profile
            try:
                vehicle = profile.vehicle
            except Vehicle.DoesNotExist:
                vehicle = None

            # Get driver documents
            documents = DriverDocument.objects.filter(user=user)
            document_serializer = DriverDocumentSerializer(documents, many=True, context={'request': request})

            profile_data = {
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "phone_number": user.phone_number,
                    "full_name": user.full_name,
                    "wallet": float(profile.wallet),
                    "todays_earnings": float(user.todays_earnings),
                },
                "profile": {
                    "first_name": profile.first_name,
                    "last_name": profile.last_name,
                    "license_number": profile.license_number,
                    "license_expiry": profile.license_expiry,
                    "city": profile.city,
                    "service_type": profile.service_type,
                    "referral_code": profile.referral_code,
                    "verification_status": profile.verification_status,
                    "wallet": float(profile.wallet),
                },
                "vehicle": {
                    "brand": vehicle.brand if vehicle else None,
                    "year": vehicle.year if vehicle else None,
                    "color": vehicle.color if vehicle else None,
                    "plate_number": vehicle.plate_number if vehicle else None,
                } if vehicle else None,
                "documents": document_serializer.data
            }

            return Response(profile_data, status=status.HTTP_200_OK)
        except DriverProfile.DoesNotExist:
            return Response({"error": "Driver profile not found"}, status=status.HTTP_404_NOT_FOUND)


class RouteListCreateView(ListCreateAPIView):
    serializer_class = RouteSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        driver_profile_id = self.request.query_params.get('driver_profile_id')
        if driver_profile_id:
            try:
                profile = DriverProfile.objects.get(id=driver_profile_id)
                return Route.objects.filter(driver_profile=profile)
            except DriverProfile.DoesNotExist:
                return Route.objects.none()
        else:
            if user.role != 'driver':
                return Route.objects.none()
            try:
                profile = user.driver_profile
                return Route.objects.filter(driver_profile=profile)
            except DriverProfile.DoesNotExist:
                return Route.objects.none()

    def perform_create(self, serializer):
        user = self.request.user
        if user.role != 'driver':
            raise serializers.ValidationError("Only drivers can create routes")
        try:
            profile = user.driver_profile
            serializer.save(driver_profile=profile)
        except DriverProfile.DoesNotExist:
            raise serializers.ValidationError("Driver profile not found")


class RouteDetailView(RetrieveUpdateDestroyAPIView):
    serializer_class = RouteSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.role != 'driver':
            return Route.objects.none()
        try:
            profile = user.driver_profile
            return Route.objects.filter(driver_profile=profile)
        except DriverProfile.DoesNotExist:
            return Route.objects.none()


class ReservationListCreateView(ListCreateAPIView):
    serializer_class = ReservationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        return Reservation.objects.filter(user=user).order_by('-created_at')

    def perform_create(self, serializer):
        logger.info("Starting reservation creation")
        # Generate tx_ref if not provided
        if not self.request.data.get('tx_ref'):
            import uuid
            tx_ref = f"ref_{uuid.uuid4().hex[:8].upper()}"
            logger.info(f"Generated tx_ref: {tx_ref}")
        else:
            tx_ref = self.request.data['tx_ref']

        # Calculate amount based on seats and base fare
        reservation_seats = self.request.data.get('reservation_seats') or self.request.data.get('selected_seats') or ''
        seats_count = len([s.strip() for s in reservation_seats.split(',') if s.strip()]) if reservation_seats else 1  # Default to 1 if no seats specified
        logger.info(f"Seats selected: {reservation_seats}, Count: {seats_count}")

        ride_type = self.request.data.get('ride_type')
        if ride_type == 'bus':
            calculated_amount = Decimal(self.request.data.get('amount', '0'))
            logger.info(f"Using provided amount for bus: {calculated_amount}")
        else:
            base_fare = Decimal('200')  # Default fare for vehicle or fallback
            route_id = self.request.data.get('route_id')
            if route_id:
                try:
                    route = Route.objects.get(id=route_id)
                    if route.fare:
                        base_fare = route.fare
                        logger.info(f"Using route fare: {base_fare}")
                except Route.DoesNotExist:
                    logger.warning(f"Route ID {route_id} not found, using default fare")
            else:
                logger.info("No route_id for vehicle, using default fare")

            calculated_amount = seats_count * base_fare
            logger.info(f"Calculated amount: {calculated_amount} (seats: {seats_count} * fare: {base_fare})")

        reservation = serializer.save(user=self.request.user, tx_ref=tx_ref, amount=calculated_amount)
        logger.info(f"Reservation created with ID: {reservation.id}, tx_ref: {tx_ref}, ride_type: {reservation.ride_type}, amount: {calculated_amount}")
        status = self.request.data.get('status', 'pending')
        reservation.status = status
        logger.info(f"Setting status to: {status}")
        if reservation.ride_type == 'vehicle':
            logger.info("Ride type is vehicle, automatically assigning driver")
            # Automatically assign vehicle reservations
            reservation.status = 'pending'
            # Check if route_id is provided in the request data
            route_id = self.request.data.get('route_id')
            logger.info(f"Route ID provided: {route_id}")
            driver = None
            if route_id:
                try:
                    # Find the specific route and assign its driver
                    selected_route = Route.objects.get(id=route_id)
                    driver = selected_route.driver_profile
                    reservation.driver = driver
                    reservation.route = selected_route
                    logger.info(f"Assigned driver from route ID: {driver.id if driver else None}")
                except Route.DoesNotExist:
                    logger.warning(f"Route ID {route_id} does not exist, falling back to random selection")
                    # If route_id is invalid, fall back to random selection
                    matching_routes = Route.objects.filter(
                        origin=reservation.pickup_location,
                        destination=reservation.destination,
                        driver_profile__verification_status='approved'
                    )
                    if matching_routes.exists():
                        selected_route = random.choice(matching_routes)
                        driver = selected_route.driver_profile
                        reservation.driver = driver
                        reservation.route = selected_route
                        logger.info(f"Assigned driver via random selection: {driver.id if driver else None}")
                    else:
                        logger.warning("No matching routes found for random selection")
            else:
                logger.info("No route_id provided, using original logic")
                # Original logic: Find approved drivers with matching route
                matching_routes = Route.objects.filter(
                    origin=reservation.pickup_location,
                    destination=reservation.destination,
                    driver_profile__verification_status='approved'
                )
                if matching_routes.exists():
                    selected_route = random.choice(matching_routes)
                    driver = selected_route.driver_profile
                    reservation.driver = driver
                    reservation.route = selected_route
                    logger.info(f"Assigned driver via original logic: {driver.id if driver else None}")
                else:
                    logger.warning("No matching routes found")

            # Populate string fields from driver for backward compatibility (or defaults if no driver)
            if driver:
                driver_user = driver.user
                reservation.driver_name = f"{driver.first_name} {driver.last_name}"
                reservation.driver_phone = driver_user.phone_number
                # For profile image, assume selfie document
                selfie_doc = DriverDocument.objects.filter(
                    user=driver_user, document_type='selfie'
                ).first()
                reservation.driver_profile_image_url = selfie_doc.file.url if selfie_doc else ''
                reservation.driver_company = "Destina Rides"  # Or from profile
                reservation.vehicle_brand = driver.vehicle.brand if hasattr(driver, 'vehicle') and driver.vehicle else 'N/A'
                reservation.vehicle_plate = driver.vehicle.plate_number if hasattr(driver, 'vehicle') and driver.vehicle else 'N/A'
                # Rating and trips: hardcoded or compute; for now, default
                reservation.driver_rating = 4.3
                reservation.driver_trips = 120
                logger.info("Driver fields populated")
            else:
                # If no driver is found, we should not proceed with crediting earnings.
                # The reservation is created but remains unassigned.
                # The logic to credit earnings will not be triggered.
                logger.warning(f"No driver assigned for reservation from {reservation.pickup_location} to {reservation.destination}. Earnings not credited.")

            reservation.save()
            logger.info(f"Reservation saved with driver: {reservation.driver.id if reservation.driver else None}")
            # Fallback for no driver assigned yet
            reservation.driver_name = 'N/A (Pending Assignment)'
            reservation.driver_phone = 'N/A'
            reservation.driver_profile_image_url = ''
            reservation.driver_company = 'N/A'
            reservation.vehicle_brand = 'N/A'
            reservation.vehicle_plate = 'N/A'
            reservation.driver_rating = 0.0
            reservation.driver_trips = 0
            logger.info("Fallback driver fields set")

            # Create notification for the driver if assigned
            if driver:
                # Credit driver's earnings immediately upon reservation creation
                driver_user = driver.user
                driver_user.todays_earnings += reservation.amount
                driver_user.save()
                logger.info(f"Credited ₦{reservation.amount} to driver {driver_user.email}. New todays_earnings: ₦{driver_user.todays_earnings}")

                Notification.objects.create(
                    driver_profile=driver,
                    message=f"New ride worth ₦{reservation.amount}: {reservation.user.full_name} ({reservation.user.phone_number}) from {reservation.pickup_location} to {reservation.destination}",
                    type='reservation',
                    reservation=reservation
                )
                logger.info(f"Notification created for driver {driver.user.email}")

            # Create notification for the user
            user_message = f"Reservation created: Your booking from {reservation.pickup_location} to {reservation.destination} on {reservation.date}"
            if reservation.ride_type == 'vehicle' and driver:
                user_message += f" with driver {driver.first_name} {driver.last_name} ({driver.user.phone_number})"
            elif reservation.ride_type == 'bus':
                user_message += " via bus service"
            UserNotification.objects.create(
                user=reservation.user,
                message=user_message,
                type='reservation'
            )
            logger.info(f"User notification created for {reservation.user.email}")
        else:
            logger.info("Not a vehicle reservation, keeping status as is")
            reservation.save()


class DriverReservationsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        if user.role != 'driver':
            return Response({"error": "Only drivers can access their reservations"}, status=status.HTTP_403_FORBIDDEN)

        try:
            profile = user.driver_profile
            reservations = Reservation.objects.filter(
                driver=profile,
                ride_type='vehicle',
                status__in=['pending', 'active', 'paid', 'completed']
            ).select_related('user', 'route').order_by('-created_at')
            serializer = ReservationSerializer(reservations, many=True, context={'request': request})
            return Response({"reservations": serializer.data}, status=status.HTTP_200_OK)
        except DriverProfile.DoesNotExist:
            return Response({"error": "Driver profile not found"}, status=status.HTTP_404_NOT_FOUND)


class GetDriverRecentReservationsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        if user.role != 'driver':
            return Response({"error": "Only drivers can access their reservations"}, status=status.HTTP_403_FORBIDDEN)

        try:
            profile = user.driver_profile
            recent_reservations = Reservation.objects.filter(
                driver=profile,
                ride_type='vehicle',
                status__in=['paid', 'completed']
            ).select_related('user', 'route').order_by('-created_at')[:3]
            serializer = ReservationSerializer(recent_reservations, many=True, context={'request': request})
            return Response({"reservations": serializer.data}, status=status.HTTP_200_OK)
        except DriverProfile.DoesNotExist:
            return Response({"error": "Driver profile not found"}, status=status.HTTP_404_NOT_FOUND)


class CompletedReservationsView(ListCreateAPIView):
    serializer_class = ReservationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        return Reservation.objects.filter(user=user, status='completed').order_by('-created_at')


class ReservationDetailView(RetrieveUpdateDestroyAPIView):
    serializer_class = ReservationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        return Reservation.objects.filter(user=user)

    def perform_update(self, serializer):
        reservation = serializer.save()
        if reservation.ride_type == 'vehicle' and reservation.status == 'paid' and reservation.driver is None:
            # Assign driver post-payment for vehicle reservations
            route_id = self.request.data.get('route_id')
            driver = None
            if route_id:
                try:
                    selected_route = Route.objects.get(id=route_id)
                    driver = selected_route.driver_profile
                    reservation.driver = driver
                    reservation.route = selected_route
                except Route.DoesNotExist:
                    matching_routes = Route.objects.filter(
                        origin=reservation.pickup_location,
                        destination=reservation.destination,
                        driver_profile__verification_status='approved'
                    )
                    if matching_routes.exists():
                        selected_route = random.choice(matching_routes)
                        driver = selected_route.driver_profile
                        reservation.driver = driver
                        reservation.route = selected_route

            if driver:
                driver_user = driver.user
                reservation.driver_name = f"{driver.first_name} {driver.last_name}"
                reservation.driver_phone = driver_user.phone_number
                selfie_doc = DriverDocument.objects.filter(
                    user=driver_user, document_type='selfie'
                ).first()
                reservation.driver_profile_image_url = selfie_doc.file.url if selfie_doc else ''
                reservation.driver_company = "Destina Rides"
                reservation.vehicle_brand = driver.vehicle.brand if hasattr(driver, 'vehicle') and driver.vehicle else 'N/A'
                reservation.vehicle_plate = driver.vehicle.plate_number if hasattr(driver, 'vehicle') and driver.vehicle else 'N/A'
                reservation.driver_rating = 4.3
                reservation.driver_trips = 120

                # Credit earnings if reservation is already paid
                if reservation.status in ['pending', 'paid']:
                    driver_user.todays_earnings += Decimal(str(reservation.amount))
                    driver_user.save()
                    Notification.objects.create(
                        driver_profile=driver,
                        message=f"Payment received: ₦{reservation.amount} added to your earnings for reservation #{reservation.id}",
                        type='payment'
                    )
            else:
                reservation.driver_name = 'N/A (Pending Assignment)'
                reservation.driver_phone = 'N/A'
                reservation.driver_profile_image_url = ''
                reservation.driver_company = 'N/A'
                reservation.vehicle_brand = 'N/A'
                reservation.vehicle_plate = 'N/A'
                reservation.driver_rating = 0.0
                reservation.driver_trips = 0

            reservation.save()


class SearchRoutesView(APIView):
    def get(self, request):
        origin = request.query_params.get('origin')
        destination = request.query_params.get('destination')
        date_str = request.query_params.get('date')

        if not origin or not destination or not date_str:
            return Response({"error": "Origin, destination, and date are required"}, status=status.HTTP_400_BAD_REQUEST)

        routes = Route.objects.filter(
            origin__iexact=origin,
            destination__iexact=destination,
            driver_profile__verification_status='approved'
        ).select_related('driver_profile__user', 'driver_profile__vehicle')

        # Always filter by date for vehicle searches
        try:
            search_date = date.fromisoformat(date_str)
            routes = routes.filter(date=search_date)
        except ValueError:
            return Response({"error": "Invalid date format. Use YYYY-MM-DD"}, status=status.HTTP_400_BAD_REQUEST)

        serializer = SearchRouteSerializer(routes, many=True, context={'request': request})
        return Response({"routes": serializer.data}, status=status.HTTP_200_OK)


class CreateFlutterwaveSubaccountView(APIView):
    # permission_classes = [IsAuthenticated]

    def post(self, request):
        logger.info(f"CreateFlutterwaveSubaccount request data: {request.data}")
        user_id = request.data.get('user_id')
        if not user_id:
            return Response({"error": "user_id is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        if user.role != 'driver':
            return Response({"error": "Only drivers can create subaccounts"}, status=status.HTTP_403_FORBIDDEN)

        try:
            profile = user.driver_profile
        except DriverProfile.DoesNotExist:
            return Response({"error": "Driver profile not found"}, status=status.HTTP_404_NOT_FOUND)

        serializer = FlutterwaveSubaccountSerializer(data=request.data)
        if serializer.is_valid():
            # Check if subaccount already exists
            if FlutterwaveSubaccount.objects.filter(driver_profile=profile).exists():
                return Response({"error": "Subaccount already exists for this driver"}, status=status.HTTP_400_BAD_REQUEST)

            # Create subaccount via Flutterwave API
            # Note: split_value is set to 0 so all funds go to main account
            # Main account controls disbursements to driver subaccounts
            subaccount_data = {
                "account_bank": serializer.validated_data['bank_code'],
                "account_number": serializer.validated_data['account_number'],
                "business_name": f"{profile.first_name} {profile.last_name}",
                "business_email": user.email,
                "business_contact": user.phone_number or "",
                "business_contact_mobile": user.phone_number or "",
                "business_mobile": user.phone_number or "",
                "country": "NG",  # Assuming Nigeria, adjust as needed
                "meta": [{"metaname": "Driver ID", "metavalue": str(profile.id)}],
                "split_type": "percentage",
                "split_value": 0.0  # 0% commission - all funds go to main account
            }

            headers = {
                "Authorization": f"Bearer {settings.FLUTTERWAVE_SECRET_KEY}",
                "Content-Type": "application/json"
            }

            try:
                response = requests.post(
                    "https://api.flutterwave.com/v3/subaccounts",
                    json=subaccount_data,
                    headers=headers
                )
                response_data = response.json()

                if response.status_code == 200 and response_data.get('status') == 'success':
                    subaccount = FlutterwaveSubaccount.objects.create(
                        driver_profile=profile,
                        subaccount_id=response_data['data']['subaccount_id'],
                        account_name=serializer.validated_data['account_name'],
                        account_number=serializer.validated_data['account_number'],
                        bank_code=serializer.validated_data['bank_code'],
                        bank_name=serializer.validated_data.get('bank_name')
                    )
                    return Response({
                        "message": "Subaccount created successfully",
                        "subaccount": FlutterwaveSubaccountSerializer(subaccount).data
                    }, status=status.HTTP_201_CREATED)
                else:
                    return Response({
                        "error": "Failed to create subaccount with Flutterwave",
                        "details": response_data
                    }, status=status.HTTP_400_BAD_REQUEST)
            except requests.RequestException as e:
                logger.error(f"Network error during Flutterwave subaccount creation: {e}")
                return Response({"error": "Network error while creating subaccount"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        logger.error(f"FlutterwaveSubaccountSerializer errors: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GetMyFlutterwaveSubaccountView(APIView):
    # permission_classes = [IsAuthenticated]

    def post(self, request):
        user_id = request.data.get('user_id')
        if not user_id:
            return Response({"error": "user_id is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        if user.role != 'driver':
            return Response({"error": "Only drivers can access their subaccount"}, status=status.HTTP_403_FORBIDDEN)

        try:
            profile = user.driver_profile
            subaccount = FlutterwaveSubaccount.objects.get(driver_profile=profile)
            serializer = FlutterwaveSubaccountSerializer(subaccount)
            return Response({"subaccount": serializer.data}, status=status.HTTP_200_OK)
        except DriverProfile.DoesNotExist:
            return Response({"error": "Driver profile not found"}, status=status.HTTP_404_NOT_FOUND)
        except FlutterwaveSubaccount.DoesNotExist:
            return Response({"subaccount": None}, status=status.HTTP_200_OK)


class RequestWithdrawalView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Comprehensive logging for withdrawal request
        logger.info(f"=== Withdrawal Request Started ===")
        logger.info(f"User ID: {request.user.id}")
        logger.info(f"User email: {request.user.email}")
        logger.info(f"User role: {request.user.role}")
        logger.info(f"Is authenticated: {request.user.is_authenticated}")
        logger.info(f"Authorization header present: {'Authorization' in request.headers}")
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            logger.info(f"Authorization header: {auth_header}")
            if auth_header.startswith('Bearer '):
                token = auth_header[7:]
                logger.info(f"Token length: {len(token)}")
                logger.info(f"Token starts with: {token[:10] if len(token) > 10 else token}...")
            else:
                logger.warning(f"Authorization header does not start with 'Bearer ': {auth_header[:20]}...")

        user = request.user
        
        # Check if user is authenticated
        if not user.is_authenticated:
            logger.error(f"User is not authenticated")
            return Response({"error": "User is not authenticated"}, status=status.HTTP_401_UNAUTHORIZED)
        
        # Check role
        if user.role != 'driver':
            logger.error(f"User role is '{user.role}', not 'driver'. Only drivers can request withdrawals")
            return Response({"error": "Only drivers can request withdrawals"}, status=status.HTTP_403_FORBIDDEN)

        # Check driver profile
        try:
            profile = user.driver_profile
            logger.info(f"Driver profile found. ID: {profile.id}, Wallet: ₦{profile.wallet}")
        except DriverProfile.DoesNotExist:
            logger.error(f"Driver profile not found for user {user.id}")
            return Response({"error": "Driver profile not found"}, status=status.HTTP_404_NOT_FOUND)

        # Log request data
        logger.info(f"Request data: {request.data}")

        serializer = WithdrawalRequestSerializer(data=request.data)
        if serializer.is_valid():
            amount = serializer.validated_data['amount']
            logger.info(f"Withdrawal amount: ₦{amount}")
            logger.info(f"Driver todays earnings: ₦{user.todays_earnings}")

            # Check if driver has sufficient earnings
            if user.todays_earnings < amount:
                logger.warning(f"Insufficient earnings. Earnings: ₦{user.todays_earnings}, Requested: ₦{amount}")
                return Response({
                    "error": "Insufficient earnings balance",
                    "earnings_balance": float(user.todays_earnings),
                    "requested_amount": float(amount)
                }, status=status.HTTP_400_BAD_REQUEST)

            # Check if subaccount exists
            subaccount_exists = FlutterwaveSubaccount.objects.filter(driver_profile=profile).exists()
            logger.info(f"Flutterwave subaccount exists: {subaccount_exists}")
            
            if not subaccount_exists:
                logger.error(f"No Flutterwave subaccount for driver {user.email}")
                return Response({"error": "Please create a Flutterwave subaccount first"}, status=status.HTTP_400_BAD_REQUEST)

            # Create the withdrawal request with status 'pending' without deducting earnings
            withdrawal = WithdrawalRequest.objects.create(
                driver_profile=profile,
                amount=amount,
                reason=serializer.validated_data.get('reason')
            )
            logger.info(f"Withdrawal request created. ID: {withdrawal.id}, Status: {withdrawal.status}")

            return Response({
                "message": "Withdrawal request submitted successfully",
                "withdrawal": WithdrawalRequestSerializer(withdrawal).data
            }, status=status.HTTP_201_CREATED)
        
        logger.error(f"Serializer validation failed: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ListMyWithdrawalRequestsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
       

        try:
            profile = user.driver_profile
            withdrawals = WithdrawalRequest.objects.filter(driver_profile=profile).order_by('-requested_at')
            serializer = WithdrawalRequestSerializer(withdrawals, many=True)
            return Response({"withdrawals": serializer.data}, status=status.HTTP_200_OK)
        except DriverProfile.DoesNotExist:
            return Response({"error": "Driver profile not found"}, status=status.HTTP_404_NOT_FOUND)


class ListAllWithdrawalRequestsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        

        withdrawals = WithdrawalRequest.objects.all().order_by('-requested_at')
        serializer = WithdrawalRequestSerializer(withdrawals, many=True)
        return Response({"withdrawals": serializer.data}, status=status.HTTP_200_OK)


class ProcessWithdrawalRequestView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, withdrawal_id):
        # Comprehensive logging for withdrawal processing
        logger.info(f"=== Withdrawal Processing Started ===")
        logger.info(f"User ID: {request.user.id}")
        logger.info(f"User email: {request.user.email}")
        logger.info(f"User role: {request.user.role}")
        logger.info(f"Is authenticated: {request.user.is_authenticated}")
        logger.info(f"Withdrawal ID: {withdrawal_id}")
        logger.info(f"Request data: {request.data}")

        user = request.user

        try:
            withdrawal = WithdrawalRequest.objects.get(id=withdrawal_id)
            logger.info(f"Withdrawal found. ID: {withdrawal.id}, Amount: ₦{withdrawal.amount}, Status: {withdrawal.status}, Driver: {withdrawal.driver_profile.user.email}")
        except WithdrawalRequest.DoesNotExist:
            logger.error(f"Withdrawal request not found: {withdrawal_id}")
            return Response({"error": "Withdrawal request not found"}, status=status.HTTP_404_NOT_FOUND)

        action = request.data.get('action')
        if action not in ['approve', 'reject']:
            logger.error(f"Invalid action: {action}")
            return Response({"error": "Invalid action. Must be 'approve' or 'reject'"}, status=status.HTTP_400_BAD_REQUEST)

        if action == 'approve':
            # Only deduct if status is changing from pending to approved
            if withdrawal.status != 'pending':
                logger.error(f"Cannot approve withdrawal {withdrawal.id} with status '{withdrawal.status}'. Only pending withdrawals can be approved.")
                return Response({"error": "Only pending withdrawals can be approved"}, status=status.HTTP_400_BAD_REQUEST)

            driver_profile = withdrawal.driver_profile
            driver_user = driver_profile.user
            logger.info(f"Processing approval for driver: {driver_user.email}, todays_earnings: ₦{driver_user.todays_earnings}")

            # Check if driver has a subaccount
            subaccount_exists = FlutterwaveSubaccount.objects.filter(driver_profile=driver_profile).exists()
            logger.info(f"Flutterwave subaccount exists: {subaccount_exists}")
            if not subaccount_exists:
                logger.error(f"No Flutterwave subaccount for driver {driver_user.email}")
                return Response({"error": "Driver does not have a Flutterwave subaccount. Please create one before approving withdrawal."}, status=status.HTTP_400_BAD_REQUEST)

            # Check if driver has sufficient earnings
            if driver_user.todays_earnings < withdrawal.amount:
                logger.warning(f"Insufficient earnings. Earnings: ₦{driver_user.todays_earnings}, Requested: ₦{withdrawal.amount}")
                return Response({"error": "Insufficient earnings balance"}, status=status.HTTP_400_BAD_REQUEST)

            # Use transaction for atomicity
            with transaction.atomic():
                # Deduct from todays_earnings
                logger.info(f"Before deduction: Driver {driver_user.email}, todays_earnings: {driver_user.todays_earnings}, deducting: {withdrawal.amount}")
                driver_user.todays_earnings -= withdrawal.amount
                driver_user.save()
                logger.info(f"After deduction: Driver {driver_user.email}, todays_earnings: {driver_user.todays_earnings}")

                # Update withdrawal status
                withdrawal.status = 'approved'
                withdrawal.processed_at = timezone.now()
                withdrawal.notes = request.data.get('notes', '')
                withdrawal.save()
                logger.info(f"Withdrawal approved. ID: {withdrawal.id}, Processed at: {withdrawal.processed_at}")

            return Response({
                "message": "Withdrawal approved and amount deducted from earnings successfully",
                "updated_earnings": float(driver_user.todays_earnings)
            }, status=status.HTTP_200_OK)

        elif action == 'reject':
            logger.info(f"Rejecting withdrawal ID: {withdrawal.id}")
            withdrawal.status = 'rejected'
            withdrawal.processed_at = timezone.now()
            withdrawal.notes = request.data.get('notes', '')
            withdrawal.save()
            logger.info(f"Withdrawal rejected. ID: {withdrawal.id}, Processed at: {withdrawal.processed_at}")
            return Response({"message": "Withdrawal request rejected"}, status=status.HTTP_200_OK)


class ListNotificationsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        if user.role != 'driver':
            return Response({"error": "Only drivers can access their notifications"}, status=status.HTTP_403_FORBIDDEN)

        try:
            profile = user.driver_profile
            notifications = Notification.objects.filter(driver_profile=profile).order_by('-created_at')
            serializer = NotificationSerializer(notifications, many=True, context={'request': request})
            unread_count = notifications.filter(is_read=False).count()
            return Response({
                "notifications": serializer.data,
                "unread_count": unread_count
            }, status=status.HTTP_200_OK)
        except DriverProfile.DoesNotExist:
            return Response({"error": "Driver profile not found"}, status=status.HTTP_404_NOT_FOUND)


class MarkNotificationReadView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, notification_id):
        user = request.user
        if user.role != 'driver':
            return Response({"error": "Only drivers can mark notifications as read"}, status=status.HTTP_403_FORBIDDEN)

        try:
            profile = user.driver_profile
            notification = Notification.objects.get(id=notification_id, driver_profile=profile)
            notification.is_read = True
            notification.save()
            return Response({"message": "Notification marked as read"}, status=status.HTTP_200_OK)
        except Notification.DoesNotExist:
            return Response({"error": "Notification not found"}, status=status.HTTP_404_NOT_FOUND)
        except DriverProfile.DoesNotExist:
            return Response({"error": "Driver profile not found"}, status=status.HTTP_404_NOT_FOUND)


class TotalDriversTodaysEarningsView(APIView):
    def get(self, request):
        total_earnings = User.objects.filter(role='driver').aggregate(total=Sum('todays_earnings'))['total'] or 0
        serializer = TotalEarningsSerializer({'total_earnings': total_earnings})
        return Response(serializer.data, status=status.HTTP_200_OK)


class DriversTodaysEarningsView(APIView):
    def get(self, request):
        drivers = User.objects.filter(role='driver').order_by('-todays_earnings')
        serializer = DriverEarningsSerializer(drivers, many=True, context={'request': request})
        return Response({
            "drivers_earnings": serializer.data
        }, status=status.HTTP_200_OK)


class TotalPaidReservationsView(APIView):
    def get(self, request):
        total_income = Reservation.objects.aggregate(total=Sum('amount'))['total'] or 0
        return Response({
            "total_paid_reservations": float(total_income)
        }, status=status.HTTP_200_OK)


class FlutterwaveWebhookView(APIView):
    def post(self, request):
        # Get raw payload and signature
        payload = request.body.decode('utf-8')
        signature = request.headers.get('verif-hash')

        if not signature:
            logger.warning("Flutterwave webhook received without signature")
            return Response({"error": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

        # Verify signature
        if not verify_flutterwave_webhook_signature(payload, signature):
            logger.warning("Flutterwave webhook signature verification failed")
            return Response({"error": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            logger.error("Invalid JSON in Flutterwave webhook payload")
            return Response({"error": "Invalid payload"}, status=status.HTTP_400_BAD_REQUEST)

        # Check if payment was successful
        if data.get('event') == 'charge.completed' and data.get('data', {}).get('status') == 'successful':
            tx_ref = data['data'].get('tx_ref')
            amount = data['data'].get('amount')

            if not tx_ref:
                logger.error("No tx_ref in successful Flutterwave webhook")
                return Response({"error": "Invalid transaction reference"}, status=status.HTTP_400_BAD_REQUEST)

            try:
                # Find reservation using the client-generated tx_ref
                reservation = Reservation.objects.get(tx_ref=tx_ref)
            except Reservation.DoesNotExist:
                logger.info(f"Reservation not found for tx_ref: {tx_ref} - likely created after payment verification by frontend")
                return Response({"message": "Payment successful, reservation will be created by frontend"}, status=status.HTTP_200_OK)

            # Use transaction to ensure atomicity
            with transaction.atomic():
                # Check if already processed
                if reservation.status in ['paid', 'completed']:
                    logger.info(f"Reservation {reservation.id} already paid, skipping")
                    return Response({"message": "Already processed"}, status=status.HTTP_200_OK)

                # Verify amount matches
                if float(reservation.amount) != float(amount):
                    logger.error(f"Amount mismatch for reservation {reservation.id}: expected {reservation.amount}, got {amount}")
                    return Response({"error": "Amount mismatch"}, status=status.HTTP_400_BAD_REQUEST)

                # Update reservation
                reservation.status = 'paid'
                reservation.payment_reference = data['data'].get('flw_ref') # Store Flutterwave's reference
                reservation.save()

                # Credit driver's earnings if driver assigned and ride_type is not 'bus'
                if reservation.driver and reservation.ride_type != 'bus':
                    driver_profile = reservation.driver

                    # Update todays_earnings for the driver
                    driver_user = driver_profile.user
                    driver_user.todays_earnings += Decimal(str(reservation.amount))
                    driver_user.save()
                    logger.info(f"Updated todays_earnings for driver {driver_user.email} by ₦{reservation.amount} to {driver_user.todays_earnings}")

                    # Create notification for driver
                    Notification.objects.create(
                        driver_profile=driver_profile,
                        message=f"Payment received: ₦{reservation.amount} added to your earnings for reservation #{reservation.id}",
                        type='payment'
                    )

                    # Create notification for user
                    user_message = f"Payment successful: Your booking from {reservation.pickup_location} to {reservation.destination} on {reservation.date} has been confirmed"
                    if reservation.ride_type == 'vehicle' and driver_profile:
                        user_message += f" with driver {driver_profile.first_name} {driver_profile.last_name} ({driver_profile.user.phone_number})"
                    elif reservation.ride_type == 'bus':
                        user_message += " via bus service"
                    UserNotification.objects.create(
                        user=reservation.user,
                        message=user_message,
                        type='payment'
                    )

                    logger.info(f"Added ₦{reservation.amount} to driver {driver_profile.user.email}'s earnings")

                elif reservation.ride_type == 'bus':
                    logger.info(f"Bus reservation {reservation.id} paid successfully, no earnings credit (Flutterwave retains funds)")

                else:
                    logger.warning(f"No driver assigned to reservation {reservation.id}, payment processed but no earnings credit")

            return Response({"message": "Payment processed successfully"}, status=status.HTTP_200_OK)

        else:
            logger.info(f"Flutterwave webhook event not processed: {data.get('event')}")
            return Response({"message": "Event not processed"}, status=status.HTTP_200_OK)


class PaymentCallbackView(APIView):
    permission_classes = [AllowAny]  # No auth needed
    template_name = 'rest_framework/payment_callback.html'

    def get(self, request):
        # Pre-fill sample values from query params (for testing)
        context = {
            'tx_ref': request.GET.get('tx_ref', ''),
            'transaction_id': request.GET.get('transaction_id', ''),
        }
        return render(request, self.template_name, context)

    def post(self, request):
        response_dict = self.handle_callback(request)
        context = {
            'tx_ref': request.POST.get('tx_ref', ''),
            'transaction_id': request.POST.get('transaction_id', ''),
            'response': response_dict,
            'json_response': json.dumps(response_dict, indent=2),
        }
        return render(request, self.template_name, context)

    def handle_callback(self, request):
        # Extract from POST or GET
        tx_ref = (request.POST if request.method == 'POST' else request.GET).get('tx_ref')
        transaction_id = (request.POST if request.method == 'POST' else request.GET).get('transaction_id')

        if not transaction_id:
            return {"status": "failed", "message": "transaction_id is required"}

        # Verify with Flutterwave
        try:
            headers = {
                "Authorization": f"Bearer {settings.FLUTTERWAVE_SECRET_KEY}",
                "Content-Type": "application/json"
            }
            resp = requests.get(
                f"https://api.flutterwave.com/v3/transactions/{transaction_id}/verify",
                headers=headers,
                timeout=10
            )
            data = resp.json()
        except Exception as e:
            logger.error(f"Flutterwave verify failed: {e}")
            return {"status": "error", "message": "Payment gateway unreachable"}

        # Even if Flutterwave says failed, we accept (per your spec)
        if data.get("status") != "success":
            logger.warning(f"Flutterwave verification failed for {transaction_id}: {data}")
            return {
                "status": "success",
                "message": "Payment processed (verification ignored)",
                "flw_status": data.get("status")
            }

        v = data.get("data", {})

        # Use tx_ref from payload or Flutterwave
        tx_ref = tx_ref or v.get("tx_ref")
        if not tx_ref:
            return {"status": "failed", "message": "tx_ref missing from payload and Flutterwave"}

        # Update or log reservation
        reservation = Reservation.objects.filter(tx_ref=tx_ref).first()
        if reservation:
            reservation.status = "paid"
            reservation.payment_reference = v.get("flw_ref")
            reservation.save()
            reservation_found = True
        else:
            logger.warning(f"Reservation NOT FOUND for tx_ref={tx_ref}")
            reservation_found = False

        return {
            "status": "success",
            "message": "Payment successful",
            "tx_ref": tx_ref,
            "flw_ref": v.get("flw_ref"),
            "amount": v.get("amount"),
            "currency": v.get("currency"),
            "reservation_found": reservation_found
        }

class RefreshDriverEarningsView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user

        if user.role == 'driver':
            target_user = user
        elif user.role == 'admin':
            user_id = request.data.get('user_id')
            if not user_id:
                return Response({"error": "user_id is required for admins"}, status=status.HTTP_400_BAD_REQUEST)
            try:
                target_user = User.objects.get(id=user_id, role='driver')
            except User.DoesNotExist:
                return Response({"error": "Driver not found"}, status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({"error": "Only drivers and admins can refresh earnings"}, status=status.HTTP_403_FORBIDDEN)

        try:
            target_profile = target_user.driver_profile
            total_earnings = Reservation.objects.filter(
                driver=target_profile,
                status='paid',
                ride_type='vehicle'
            ).aggregate(total=Sum('amount'))['total'] or 0
            target_user.todays_earnings = total_earnings
            target_user.save()
            logger.info(f"Refreshed todays_earnings for driver {target_user.email} to {total_earnings}")
            return Response({
                "message": "Earnings refreshed successfully",
                "todays_earnings": float(target_user.todays_earnings)
            }, status=status.HTTP_200_OK)
        except DriverProfile.DoesNotExist:
            return Response({"error": "Driver profile not found"}, status=status.HTTP_404_NOT_FOUND)


class ListUserNotificationsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        notifications = UserNotification.objects.filter(user=user).order_by('-created_at')
        serializer = UserNotificationSerializer(notifications, many=True, context={'request': request})
        unread_count = notifications.filter(is_read=False).count()
        return Response({
            "notifications": serializer.data,
            "unread_count": unread_count
        }, status=status.HTTP_200_OK)


class MarkUserNotificationReadView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, notification_id):
        user = request.user
        try:
            notification = UserNotification.objects.get(id=notification_id, user=user)
            notification.is_read = True
            notification.save()
            return Response({"message": "Notification marked as read"}, status=status.HTTP_200_OK)
        except UserNotification.DoesNotExist:
            return Response({"error": "Notification not found"}, status=status.HTTP_404_NOT_FOUND)


class CreateUserNotificationView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = UserNotificationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class DisableUserView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        user_id = request.data.get('user_id')
        if not user_id:
            return Response({"error": "user_id is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(id=user_id)
            user.is_active = False
            user.save()
            return Response({"message": f"User {user.email} disabled successfully"}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)


class DeleteUserView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        user_id = request.data.get('user_id')
        if not user_id:
            return Response({"error": "user_id is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(id=user_id)
            user.delete()
            return Response({"message": f"User {user.email} deleted successfully"}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)


class EnableUserView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        user_id = request.data.get('user_id')
        if not user_id:
            return Response({"error": "user_id is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(id=user_id)
            user.is_active = True
            user.save()
            return Response({"message": f"User {user.email} enabled successfully"}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)


class UpdateUserLocationView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        latitude = request.data.get('latitude')
        longitude = request.data.get('longitude')

        # Log missing payload for debugging
        if latitude is None or longitude is None:
            logger.warning(f"UpdateUserLocationView: Missing latitude/longitude - user={getattr(user, 'id', None)}, data={request.data}")
            return Response({"error": "latitude and longitude are required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            latitude = float(latitude)
            longitude = float(longitude)
        except (ValueError, TypeError):
            logger.warning(f"UpdateUserLocationView: Invalid latitude/longitude - user={getattr(user, 'id', None)}, lat={latitude}, lon={longitude}")
            return Response({"error": "Invalid latitude or longitude"}, status=status.HTTP_400_BAD_REQUEST)

        user.last_location = {
            'latitude': latitude,
            'longitude': longitude,
            'timestamp': timezone.now().isoformat()
        }
        try:
            user.save()
        except Exception as e:
            logger.error(f"UpdateUserLocationView: Failed to save location for user={getattr(user, 'id', None)}: {str(e)}")
            return Response({"error": "Failed to save location"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        logger.info(f"UpdateUserLocationView: Updated location for user={user.id} -> {user.last_location}")
        # Return the saved location to make it easy to verify from the client
        return Response({"message": "Location updated successfully", "last_location": user.last_location}, status=status.HTTP_200_OK)


class GetAllUserLocationsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user


        role_filter = request.query_params.get('role')  # Optional: filter by 'user' or 'driver'
        users = User.objects.filter(is_active=True)
        if role_filter in ['user', 'driver']:
            users = users.filter(role=role_filter)

        locations = []
        for u in users:
            if u.last_location:
                locations.append({
                    'user_id': u.id,
                    'email': u.email,
                    'role': u.role,
                    'full_name': u.full_name,
                    'latitude': u.last_location.get('latitude'),
                    'longitude': u.last_location.get('longitude'),
                    'timestamp': u.last_location.get('timestamp')
                })

        return Response({"locations": locations}, status=status.HTTP_200_OK)





class GetUserLocationView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, user_id):
        try:
            user = User.objects.get(id=user_id)
            if not user.last_location:
                return Response({"error": "Location not available"}, status=status.HTTP_404_NOT_FOUND)

            location = user.last_location
            timestamp_str = location.get('timestamp')
            is_stale = True
            if timestamp_str:
                from datetime import datetime
                timestamp = datetime.fromisoformat(timestamp_str)
                now = timezone.now()
                is_stale = (now - timestamp).total_seconds() > 300  # 5 minutes

            return Response({
                "user_id": user.id,
                "latitude": location.get('latitude'),
                "longitude": location.get('longitude'),
                "timestamp": location.get('timestamp'),
                "is_stale": is_stale
            }, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)


class UpdateUserLocationByIdView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, user_id):
        user = request.user
        

        try:
            target_user = User.objects.get(id=user_id)
            latitude = request.data.get('latitude')
            longitude = request.data.get('longitude')

            if latitude is None or longitude is None:
                return Response({"error": "latitude and longitude are required"}, status=status.HTTP_400_BAD_REQUEST)

            try:
                latitude = float(latitude)
                longitude = float(longitude)
            except (ValueError, TypeError):
                return Response({"error": "Invalid latitude or longitude"}, status=status.HTTP_400_BAD_REQUEST)

            target_user.last_location = {
                'latitude': latitude,
                'longitude': longitude,
                'timestamp': timezone.now().isoformat()
            }
            target_user.save()

            return Response({"message": "Location updated successfully", "last_location": target_user.last_location}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
