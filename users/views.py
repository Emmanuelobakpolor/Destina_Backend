from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import get_user_model
from .serializers import DriverDocumentSerializer, SignupSerializer, VerifyDriverSignupWithFilesSerializer, VerifySignupSerializer, LoginSerializer, VerifyLoginSerializer, DriverProfileUpdateSerializer, VehicleUpdateSerializer, UserProfileUpdateSerializer, UserSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
import random
from .models import DriverProfile, Vehicle, VerificationCode, DriverDocument
import requests
from django.conf import settings
from django.utils import timezone
from datetime import date
import logging

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
                vehicle_fields = ['brand', 'year', 'manufacturer', 'color', 'plate_number']
                for field in vehicle_fields:
                    if serializer.validated_data.get(field):
                        setattr(vehicle, field, serializer.validated_data[field])
                vehicle.save()
                print(f"Vehicle saved: {vehicle.brand} {vehicle.plate_number}")

                file_fields = [
                    ('license_document', serializer.validated_data.get('license_document'), serializer.validated_data.get('license_expiry')),
                    ('selfie', serializer.validated_data.get('selfie'), None),
                    ('road_worthiness', serializer.validated_data.get('road_worthiness'), None),
                    ('insurance_certificate', serializer.validated_data.get('insurance_certificate'), None),
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


class GetAdminDriverDocumentsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, user_id):
        user = request.user
        if user.role != 'admin':
            return Response({"error": "Only admins can access driver documents"}, status=status.HTTP_403_FORBIDDEN)

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
