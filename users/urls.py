from django.urls import path
from .views import GetMyDriverProfileView, InitiateSignupView, VerifySignupView, LoginView, VerifyLoginView, VerifyDriverSignupWithFilesView, ResendOTPView, UpdateDriverProfileView, UpdateVehicleView, UpdateUserProfileView, UploadUserProfilePictureView, DriverVerificationStatusView, GetDriverVerificationStatusByIdView, GetAdminDriverDocumentsView, GetMyDriverDocumentsView, UserStatsView, ListUsersView, ListDriversView, GetDriverProfileView, RouteListCreateView, RouteDetailView, ReservationListCreateView, ReservationDetailView, SearchRoutesView

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
    path('driver-verification-status/<int:user_id>/', GetDriverVerificationStatusByIdView.as_view(), name='driver-verification-status-by-id'),
    path('admin-driver-documents/<int:user_id>/', GetAdminDriverDocumentsView.as_view(), name='admin-driver-documents'),
    path('my-documents/', GetMyDriverDocumentsView.as_view(), name='my-documents'),
    path('user-stats/', UserStatsView.as_view(), name='user-stats'),
    path('list-users/', ListUsersView.as_view(), name='list-users'),
    path('list-drivers/', ListDriversView.as_view(), name='list-drivers'),
    path('driver-profile/<int:user_id>/', GetDriverProfileView.as_view(), name='driver-profile'),
    path('my-driver-profile/', GetMyDriverProfileView.as_view(), name='my-driver-profile'),
    path('routes/', RouteListCreateView.as_view(), name='route-list-create'),
    path('routes/<int:pk>/', RouteDetailView.as_view(), name='route-detail'),
    path('reservations/', ReservationListCreateView.as_view(), name='reservation-list-create'),
    path('reservations/<int:pk>/', ReservationDetailView.as_view(), name='reservation-detail'),
    path('search-routes/', SearchRoutesView.as_view(), name='search-routes'),
]
