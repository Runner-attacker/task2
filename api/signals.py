from django.db.models.signals import pre_save, post_save
from django.dispatch import receiver
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail

from .models import CustomUser
import uuid


@receiver(pre_save, sender=CustomUser)
def create_referal_code(sender, instance, **kwargs):
    if not instance.pk and not instance.referral_code:
        instance.referral_code = str(uuid.uuid4())[:8]
        print("Referral code generated:", instance.referral_code)


@receiver(post_save, sender=CustomUser)
def send_verification_email(sender, instance, created, **kwargs):
    if created:
        token = default_token_generator.make_token(instance)
        uid = urlsafe_base64_encode(force_bytes(instance.pk))
        verification_link = f"api/verify-email/{uid}/{token}/"
        # printing the variables to make sure they are correct
        print("From Email:", "koirala24sahil@gmail.com")
        print("Recipient Email:", instance.email)
        print("Verification Link:", verification_link)
        try:
            send_mail(
                subject="Verify Your Email",
                message=f"Click the link to verify your email: {verification_link}",
                from_email="koirala24sahil@gmail.com",
                recipient_list=[instance.email],
                fail_silently=False,
            )
            print("Email sent successfully! via signal")
        except Exception as e:
            print(f"Failed to send email: {e}")
