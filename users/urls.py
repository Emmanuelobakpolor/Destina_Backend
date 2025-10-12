from django.urls import path
from .views import InitiateSignupView, VerifySignupView, LoginView, VerifyLoginView, InitiateDriverSignupView, VerifyDriverSignupView, VerifyDriverSignupWithFilesView, ResendOTPView, UpdateDriverProfileView, UpdateVehicleView, UpdateUserProfileView, DriverVerificationStatusView

urlpatterns = [
    path('initiate-signup/', InitiateSignupView.as_view(), name='initiate-signup'),
    path('verify-signup/', VerifySignupView.as_view(), name='verify-signup'),
    path('login/', LoginView.as_view(), name='login'),
    path('verify-login/', VerifyLoginView.as_view(), name='verify-login'),
    path('initiate-driver-signup/', InitiateDriverSignupView.as_view(), name='initiate-driver-signup'),
    path('verify-driver-signup/', VerifyDriverSignupView.as_view(), name='verify-driver-signup'),
    path('verify-driver-signup-with-files/', VerifyDriverSignupWithFilesView.as_view(), name='verify-driver-signup-with-files'),
    path('resend-otp/', ResendOTPView.as_view(), name='resend-otp'),
    path('update-driver-profile/', UpdateDriverProfileView.as_view(), name='update-driver-profile'),
    path('update-vehicle/', UpdateVehicleView.as_view(), name='update-vehicle'),
    path('update-user-profile/', UpdateUserProfileView.as_view(), name='update-user-profile'),
    path('driver-verification-status/', DriverVerificationStatusView.as_view(), name='driver-verification-status'),
]
