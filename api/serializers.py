from rest_framework import serializers
from .models import CustomUser
import uuid
from django.core.exceptions import ValidationError


class UserSerializer(serializers.ModelSerializer):
    referral_code = serializers.CharField(read_only=True)
    referred_by_code = serializers.CharField(write_only=True, required=False)
    referred_by = serializers.StringRelatedField(read_only=True)

    class Meta:
        model = CustomUser
        fields = [
            "username",
            "email",
            "avatar",
            "phone_number",
            "referral_code",
            "referred_by_code",
            "password",
            "referred_by",
        ]
        extra_kwargs = {
            "password": {"write_only": True},
            "username": {"required": True},
        }

    def validate_email(self, value):
        if CustomUser.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email is already in use.")
        return value

    def validate_password(self, value):
        if len(value) < 8:
            raise serializers.ValidationError(
                "Password must be at least 8 characters long."
            )
        if not any(char in "@$!%*?&" for char in value):
            raise serializers.ValidationError(
                "Password must contain at least one special character."
            )
        return value

    def create(self, validated_data):
        password = validated_data.pop("password")
        referral_code = validated_data.pop("referred_by_code", None)

        user = CustomUser(**validated_data)
        user.set_password(password)

        if referral_code:
            try:
                referrer = CustomUser.objects.get(referral_code=referral_code)
                user.referred_by = referrer
            except CustomUser.DoesNotExist:
                raise serializers.ValidationError(
                    {"referred_by_code": "Invalid referral code."}
                )

        user.save()
        return user

    def update(self, instance, validated_data):
        # Update the user instance with validated data
        instance.username = validated_data.get("username", instance.username)
        instance.email = validated_data.get("email", instance.email)
        instance.phone_number = validated_data.get(
            "phone_number", instance.phone_number
        )
        instance.avatar = validated_data.get("avatar", instance.avatar)
        instance.save()
        return instance


class ReferredUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ["username", "email", "phone_number"]
