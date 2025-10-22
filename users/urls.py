from django.urls import path
from .views import InitiateSignupView, VerifySignupView, LoginView, VerifyLoginView, VerifyDriverSignupWithFilesView, ResendOTPView, UpdateDriverProfileView, UpdateVehicleView, UpdateUserProfileView, UploadUserProfilePictureView, DriverVerificationStatusView, GetAdminDriverDocumentsView, GetMyDriverDocumentsView, UserStatsView, ListUsersView, ListDriversView

urlpatterns = [
    path('initiate-signup/', InitiateSignupView.as_view(), name='initiate-signup'),
    path('verify-signup/', VerifySignupView.as_view(), name='verify-signup'),
    path('login/', LoginView.as_view(), name='login'),
    path('verify-login/', VerifyLoginView.as_view(), name='verify-login'),
    path('verify-driver-signup-with-files/', VerifyDriverSignupWithFilesView.as_view(), name='verify-driver-signup-with-files'),
    path('resend-otp/', ResendOTPView.as_view(), name='resend-otp'),
    path('update-driver-profile/', UpdateDriverProfileView.as_view(), name='update-driver-profile'),
    path('update-vehicle/', UpdateVehicleView.as_view(), name='update-vehicle'),
    path('update-user-profile/', UpdateUserProfileView.as_view(), name='update-user-profile'),
    path('upload-user-profile-picture/', UploadUserProfilePictureView.as_view(), name='upload-user-profile-picture'),
    path('driver-verification-status/', DriverVerificationStatusView.as_view(), name='driver-verification-status'),
    path('admin-driver-documents/<int:user_id>/', GetAdminDriverDocumentsView.as_view(), name='admin-driver-documents'),
    path('my-documents/', GetMyDriverDocumentsView.as_view(), name='my-documents'),
    path('user-stats/', UserStatsView.as_view(), name='user-stats'),
    path('list-users/', ListUsersView.as_view(), name='list-users'),
    path('list-drivers/', ListDriversView.as_view(), name='list-drivers'),
]
