from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import get_user_model
from .serializers import DriverDocumentSerializer, SignupSerializer, VerifyDriverSignupWithFilesSerializer, VerifySignupSerializer, LoginSerializer, VerifyLoginSerializer, DriverProfileUpdateSerializer, VehicleUpdateSerializer, UserProfileUpdateSerializer, UserSerializer, RouteSerializer, ReservationSerializer, SearchRouteSerializer, FlutterwaveSubaccountSerializer, WithdrawalRequestSerializer, NotificationSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from django.db.models import Sum
import random
from .models import DriverProfile, Vehicle, VerificationCode, DriverDocument, Route, Reservation, FlutterwaveSubaccount, WithdrawalRequest, Notification
from rest_framework.generics import ListCreateAPIView, RetrieveUpdateDestroyAPIView
import requests
from django.conf import settings
from django.utils import timezone
from datetime import date
import logging
import json
from django.db import transaction
from .utils import verify_flutterwave_webhook_signature
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator


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
        reservation = serializer.save(user=self.request.user, tx_ref=tx_ref)
        logger.info(f"Reservation created with ID: {reservation.id}, tx_ref: {tx_ref}, ride_type: {reservation.ride_type}")
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

            reservation.save()
            logger.info(f"Reservation saved with driver: {reservation.driver.id if reservation.driver else None}")

            # Create notification for the driver if assigned
            if driver:
                Notification.objects.create(
                    driver_profile=driver,
                    message=f"New reservation: {reservation.user.full_name} booked a ride from {reservation.pickup_location} to {reservation.destination}",
                    type='reservation'
                )
                logger.info(f"Notification created for driver {driver.user.email}")
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

        if not origin or not destination:
            return Response({"error": "Origin and destination are required"}, status=status.HTTP_400_BAD_REQUEST)

        routes = Route.objects.filter(
            origin__iexact=origin,
            destination__iexact=destination,
            driver_profile__verification_status='approved'
        ).select_related('driver_profile__user', 'driver_profile__vehicle')

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
            logger.info(f"Authorization header format: {request.headers['Authorization'][:20]}...")
        
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
            logger.info(f"Driver wallet balance: ₦{profile.wallet}")

            # Check if driver has sufficient balance
            if profile.wallet < amount:
                logger.warning(f"Insufficient balance. Wallet: ₦{profile.wallet}, Requested: ₦{amount}")
                return Response({
                    "error": "Insufficient wallet balance",
                    "wallet_balance": float(profile.wallet),
                    "requested_amount": float(amount)
                }, status=status.HTTP_400_BAD_REQUEST)

            # Check if subaccount exists
            subaccount_exists = FlutterwaveSubaccount.objects.filter(driver_profile=profile).exists()
            logger.info(f"Flutterwave subaccount exists: {subaccount_exists}")
            
            if not subaccount_exists:
                logger.error(f"No Flutterwave subaccount for driver {user.email}")
                return Response({"error": "Please create a Flutterwave subaccount first"}, status=status.HTTP_400_BAD_REQUEST)

            # Create withdrawal request
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
        user = request.user
        

        try:
            withdrawal = WithdrawalRequest.objects.get(id=withdrawal_id)
        except WithdrawalRequest.DoesNotExist:
            return Response({"error": "Withdrawal request not found"}, status=status.HTTP_404_NOT_FOUND)

        action = request.data.get('action')
        if action not in ['approve', 'reject']:
            return Response({"error": "Invalid action. Must be 'approve' or 'reject'"}, status=status.HTTP_400_BAD_REQUEST)

        if action == 'approve':
            # Check if subaccount exists
            try:
                subaccount = FlutterwaveSubaccount.objects.get(driver_profile=withdrawal.driver_profile)
            except FlutterwaveSubaccount.DoesNotExist:
                return Response({"error": "Driver subaccount not found"}, status=status.HTTP_404_NOT_FOUND)

            # Check if driver has sufficient balance
            if withdrawal.driver_profile.wallet < withdrawal.amount:
                return Response({"error": "Insufficient wallet balance"}, status=status.HTTP_400_BAD_REQUEST)

            # Process transfer via Flutterwave
            transfer_data = {
                "account_bank": subaccount.bank_code,
                "account_number": subaccount.account_number,
                "amount": float(withdrawal.amount),
                "narration": f"Withdrawal for {withdrawal.driver_profile.user.email}",
                "currency": "NGN",
                "reference": f"withdrawal_{withdrawal.id}_{timezone.now().strftime('%Y%m%d%H%M%S')}",
                "callback_url": f"{settings.BASE_URL}/api/withdrawal-callback/",
                "debit_currency": "NGN"
            }

            headers = {
                "Authorization": f"Bearer {settings.FLUTTERWAVE_SECRET_KEY}",
                "Content-Type": "application/json"
            }

            try:
                response = requests.post(
                    "https://api.flutterwave.com/v3/transfers",
                    json=transfer_data,
                    headers=headers
                )
                response_data = response.json()

                if response.status_code == 200 and response_data.get('status') == 'success':
                    # Deduct from wallet
                    withdrawal.driver_profile.wallet -= withdrawal.amount
                    withdrawal.driver_profile.save()

                    # Update withdrawal status
                    withdrawal.status = 'processed'
                    withdrawal.processed_at = timezone.now()
                    withdrawal.notes = request.data.get('notes', '')
                    withdrawal.save()

                    return Response({
                        "message": "Withdrawal processed successfully",
                        "transfer_id": response_data['data']['id']
                    }, status=status.HTTP_200_OK)
                else:
                    return Response({
                        "error": "Failed to process transfer with Flutterwave",
                        "details": response_data
                    }, status=status.HTTP_400_BAD_REQUEST)
            except requests.RequestException as e:
                return Response({"error": "Network error while processing transfer"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        elif action == 'reject':
            withdrawal.status = 'rejected'
            withdrawal.processed_at = timezone.now()
            withdrawal.notes = request.data.get('notes', '')
            withdrawal.save()
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
        return Response({
            "total_todays_earnings": float(total_earnings)
        }, status=status.HTTP_200_OK)


class DriversTodaysEarningsView(APIView):
    def get(self, request):
        drivers_data = User.objects.filter(role='driver').values('id', 'full_name', 'email', 'todays_earnings').order_by('-todays_earnings')

        drivers_earnings = []
        for item in drivers_data:
            driver_name = item['full_name'] or item['email']
            drivers_earnings.append({
                "driver_id": item['id'],
                "driver_name": driver_name,
                "todays_earnings": float(item['todays_earnings'] or 0)
            })

        return Response({
            "drivers_earnings": drivers_earnings
        }, status=status.HTTP_200_OK)


class TotalPaidReservationsView(APIView):
    def get(self, request):
        total_income = Reservation.objects.aggregate(total=Sum('amount'))['total'] or 0
        return Response({
            "total_paid_reservations": float(total_income)
        }, status=status.HTTP_200_OK)


@method_decorator(csrf_exempt, name='dispatch')
class FlutterwaveWebhookView(APIView):
    def post(self, request):
        # Get raw payload and signature
        payload = request.body.decode('utf-8')
        signature = request.headers.get('verif-hash')

        logger.info(f"Flutterwave webhook received. Payload length: {len(payload)}, Signature: {signature}")

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
                logger.error(f"Reservation not found for tx_ref: {tx_ref}")
                return Response({"error": "Reservation not found"}, status=status.HTTP_404_NOT_FOUND)

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

                # Credit driver's wallet if driver assigned and ride_type is not 'bus'
                if reservation.driver and reservation.ride_type != 'bus':
                    driver_profile = reservation.driver
                    driver_profile.wallet += reservation.amount
                    driver_profile.save()

                    # Create notification for driver
                    Notification.objects.create(
                        driver_profile=driver_profile,
                        message=f"Payment received: ₦{reservation.amount} credited to your wallet for reservation #{reservation.id}",
                        type='payment'
                    )

                    logger.info(f"Credited ₦{reservation.amount} to driver {driver_profile.user.email}'s profile wallet")

                elif reservation.ride_type == 'bus':
                    logger.info(f"Bus reservation {reservation.id} paid successfully, no wallet credit (Flutterwave retains funds)")

                else:
                    logger.warning(f"No driver assigned to reservation {reservation.id}, payment processed but no wallet credit")

            return Response({"message": "Payment processed successfully"}, status=status.HTTP_200_OK)

        else:
            logger.info(f"Flutterwave webhook event not processed: {data.get('event')}")
            return Response({"message": "Event not processed"}, status=status.HTTP_200_OK)


class PaymentCallbackView(APIView):
    def get(self, request):
        tx_ref = request.query_params.get('tx_ref')
        flw_ref = request.query_params.get('flw_ref')
        if not tx_ref and not flw_ref:
            return create_error_response('invalid_data', "Transaction reference missing", status.HTTP_400_BAD_REQUEST)

        reservation = None
        lookup_ref = tx_ref or flw_ref
        lookup_field = 'tx_ref' if tx_ref else 'payment_reference'

        try:
            # Find the reservation by tx_ref first, fallback to flw_ref (payment_reference)
            reservation = Reservation.objects.get(**{lookup_field: lookup_ref})
        except Reservation.DoesNotExist:
            logger.error(f"PaymentCallbackView: Reservation not found for {lookup_field}: {lookup_ref}")
            return create_error_response('reservation_not_found', f"{lookup_field}: {lookup_ref}", status.HTTP_404_NOT_FOUND)

        # Verify payment with Flutterwave
        headers = {
            "Authorization": f"Bearer {settings.FLUTTERWAVE_SECRET_KEY}",
            "Content-Type": "application/json"
        }
        try:
            transaction_id = request.query_params.get('transaction_id') or flw_ref
            if not transaction_id:
                return create_error_response('invalid_data', "Transaction ID missing for verification", status.HTTP_400_BAD_REQUEST)
            response = requests.get(
                f"https://api.flutterwave.com/v3/transactions/{transaction_id}/verify",
                headers=headers
            )
            verification_data = response.json()
        except requests.RequestException as e:
            logger.error(f"Error verifying payment: {e}")
            return create_error_response('network_error', str(e), status.HTTP_500_INTERNAL_SERVER_ERROR)

        if verification_data.get('status') == 'success' and verification_data.get('data', {}).get('status') == 'successful':
            amount = verification_data['data']['amount']
            stored_flw_ref = verification_data['data']['flw_ref']
            # Verify amount matches
            if float(reservation.amount) != float(amount):
                logger.error(f"Amount mismatch for reservation {reservation.id}: expected {reservation.amount}, got {amount}")
                return create_error_response('invalid_data', f"Amount mismatch: {amount} vs {reservation.amount}", status.HTTP_400_BAD_REQUEST)
            # Update reservation if not already processed
            if reservation.status not in ['paid', 'completed']:
                with transaction.atomic():
                    reservation.status = 'paid'
                    if not reservation.payment_reference:
                        reservation.payment_reference = stored_flw_ref  # Store Flutterwave's reference
                    reservation.save()

                    # Credit driver's wallet if driver assigned and ride_type is not 'bus'
                    if reservation.driver and reservation.ride_type != 'bus':
                        driver_profile = reservation.driver
                        driver_profile.wallet += reservation.amount
                        driver_profile.save()

                        # Create notification for driver
                        Notification.objects.create(
                            driver_profile=driver_profile,
                            message=f"Payment received: ₦{reservation.amount} credited to your wallet for reservation #{reservation.id}",
                            type='payment'
                        )

            # For mobile app, this might redirect to a deep link or show success message
            # For now, return JSON response that the app can handle
            return Response({
                "message": "Payment successful",
                "reservation_id": reservation.id,
                "status": "paid",
                "tx_ref": reservation.tx_ref,
                "flw_ref": reservation.payment_reference
            }, status=status.HTTP_200_OK)
        else:
            return create_error_response('invalid_data', verification_data, status.HTTP_400_BAD_REQUEST)
