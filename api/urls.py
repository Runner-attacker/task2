from django.urls import path
from api.views import (
    CustomUserRegistrationView,
    EmailVerificationView,
    Login,
    LogoutView,
    PasswordResetConfirmResetView,
    PasswordResetRequestView,
    ReferredUsersView,
    UserDetailView,
)

urlpatterns = [
    path("register/", CustomUserRegistrationView.as_view(), name="register"),
    path(
        "verify-email/<uidb64>/<token>/",
        EmailVerificationView.as_view(),
        name="verify_email",
    ),
    path(
        "login/",
        Login.as_view(),
        name="login",
    ),
    path("user-detail/", UserDetailView.as_view(), name="user_detail"),
    path(
        "request-password-reset/",
        PasswordResetRequestView.as_view(),
        name="request-password-reset",
    ),
    path(
        "reset-password/<uidb64>/<token>/",
        PasswordResetConfirmResetView.as_view(),
        name="reset-password",
    ),
    path(
        "referred-users/",
        ReferredUsersView.as_view(),
        name="referred-users",
    ),
    path(
        "logout/",
        LogoutView.as_view(),
        name="logout",
    ),
]
