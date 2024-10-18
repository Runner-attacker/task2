from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from rest_framework import generics, status
from rest_framework.response import Response
from .models import CustomUser
from rest_framework.permissions import AllowAny, IsAuthenticated
from .serializers import ReferredUserSerializer, UserSerializer
from rest_framework.views import APIView
from rest_framework import permissions
from django.contrib.auth import authenticate
from rest_framework.pagination import PageNumberPagination

from rest_framework_simplejwt.tokens import RefreshToken

from django.utils.http import urlsafe_base64_decode


class CustomPagination(PageNumberPagination):
    page_size = 5
    page_size_query_param = "page_size"
    max_page_size = 100


class CustomUserRegistrationView(generics.CreateAPIView):
    serializer_class = UserSerializer
    permission_classes = [AllowAny]

    # def perform_create(self, serializer):
    #     # This method ovverrides the default perform_create method from CreateAPIView
    #     user = serializer.save()
    #     token = default_token_generator.make_token(user)
    #     uid = urlsafe_base64_encode(force_bytes(user.pk))
    #     verification_link = f"{self.request.scheme}://{self.request.get_host()}/api/verify-email/{uid}/{token}/"

    #     # Printing the variables to make sure they are correct
    #     print("From Email:", "koirala24sahil@gmail.com")
    #     print("Recipient Email:", user.email)
    #     print("Verification Link:", verification_link)

    #     # Sending the verification email
    #     print(type(user.email))
    #     print(user.email)

    #     try:

    #         send_mail(
    #             subject="Verify Your Email",
    #             message=f"Click the link to verify your email: {verification_link}",
    #             from_email="koirala24sahil@gmail.com",
    #             recipient_list=[user.email],
    #             fail_silently=False,
    #         )
    #         print("Email sent successfully!")
    #     except Exception as e:
    #         print(f"Failed to send email: {e}")


class EmailVerificationView(generics.GenericAPIView):
    def get(self, request, uidb64, token):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = CustomUser.objects.get(pk=uid)
            if default_token_generator.check_token(
                user, token
            ):  # checks if the provided token is valid for the user
                user.is_verified = True
                user.save()
                return Response(
                    {"message": "Email verified successfully"},
                    status=status.HTTP_200_OK,
                )
            else:
                return Response(
                    {"message": "Email verification failed"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist):
            return Response(
                {"message": "Invalid verification link"},
                status=status.HTTP_400_BAD_REQUEST,
            )


class Login(APIView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request):
        email = request.data["email"]
        password = request.data["password"]
        user = CustomUser.objects.filter(email=email).first()
        if user and not user.is_verified:
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            verification_link = f"{self.request.scheme}://{self.request.get_host()}/api/verify-email/{uid}/{token}/"
            try:

                send_mail(
                    subject="Verify Your Email",
                    message=f"Click the link to verify your email: {verification_link}",
                    from_email="koirala24sahil@gmail.com",
                    recipient_list=[user.email],
                    fail_silently=False,
                    html_message=f"""
                    <p>Hello,</p>
                    <p>Thank you for registering. Please click the link below to verify your email address:</p>
                    <p><a href="{verification_link}">Verify Email</a></p>
                    <p>If the above link does not work, copy and paste the following URL into your browser:</p>
                    <p>{verification_link}</p>
                    """,
                )
                return Response(
                    {
                        "detail": "Your email is not verified yet. A verification email has been sent to your email."
                    },
                    status=status.HTTP_401_UNAUTHORIZED,
                )
            except Exception as e:
                return Response(
                    {"detail": f"Failed to send verification email: {e}"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )
        # Authenticate the verified user
        user = authenticate(email=email, password=password)
        if user:
            refresh = RefreshToken.for_user(user)
            return Response(
                {
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                }
            )
        else:
            return Response(
                {"detail": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED
            )


class UserDetailView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        serializer = UserSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request):
        user = request.user
        serilizer = UserSerializer(user, data=request.data)
        if serilizer.is_valid():
            serilizer.save()
            return Response(serilizer.data, status=status.HTTP_200_OK)
        return Response(serilizer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request):
        user = request.user
        serilizer = UserSerializer(user, data=request.data, partial=True)
        if serilizer.is_valid():
            serilizer.save()
            return Response(serilizer.data, status=status.HTTP_200_OK)
        return Response(serilizer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetRequestView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        email = request.data.get("email")
        user = CustomUser.objects.filter(email=email).first()
        if user:
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            reset_link = f"{self.request.scheme}://{self.request.get_host()}/api/reset-password/{uid}/{token}/"
            # send password reset email
            send_mail(
                subject="Password Reset Request",
                message=f"Click the link to reset your password: {reset_link}",
                from_email="koirala24sahil@gmail.com",
                recipient_list=[user.email],
                fail_silently=False,
                html_message=f"""
                <p>Hello,</p>
                <p>You have requested to reset your password. Please click the link below to reset your password:</p>
                <p><a href="{reset_link}">Reset Password</a></p>
                <p>If the above link does not work, copy and paste the following URL into your browser:</p>
                <p>{reset_link}</p>
                """,
            )
            return Response(
                {"detail": "Password reset link has been sent to your email."},
                status=status.HTTP_200_OK,
            )

        return Response(
            {"detail": "No account associated with this email."},
            status=status.HTTP_404_NOT_FOUND,
        )


class PasswordResetConfirmResetView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, uidb64, token):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = CustomUser.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            new_password = request.data.get("new_password")
            user.set_password(new_password)
            user.save()
            return Response(
                {"detail": "Password has been reset successfully."},
                status=status.HTTP_200_OK,
            )
        return Response(
            {"detail": "Invalid token or user ID."}, status=status.HTTP_400_BAD_REQUEST
        )


class ReferredUsersView(APIView):
    permission_classes = [IsAuthenticated]
    pagination_class = PageNumberPagination

    def get(self, request):

        user = request.user

        # Finds all the users who are  referred by the loggedin user
        referred_users = CustomUser.objects.filter(referred_by=user)

        serializer = ReferredUserSerializer(referred_users, many=True)

        return Response(
            {
                "user": user.username,
                "referral_code": user.referral_code,
                "referred_users": serializer.data,
            }
        )


class LogoutView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            # Making sure refresh_token is present in the request data
            refresh_token = request.data["refresh_token"]
            token = RefreshToken(refresh_token)

            # Blacklist the refresh token
            token.blacklist()

            return Response({"detail": "Logout successful."}, status=status.HTTP_200_OK)
        except KeyError:
            return Response(
                {"detail": "Refresh token is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)
