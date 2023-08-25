from django.db import models
from .basemodel import *
import secrets
from django.contrib.auth.models import AbstractUser, User
from django_rest_passwordreset.signals import reset_password_token_created
from django.dispatch import receiver
from django.core.mail import send_mail
from django.urls import reverse


@receiver(reset_password_token_created)
def password_reset_token_created(sender, instance, reset_password_token, *args, **kwargs):
    email_plaintext_message = "{}?token={}".format(reverse('password_reset:reset-password-request'), reset_password_token.key)
    send_mail(
        # title:
        "Password Reset for {title}".format(title="project1.com"),
        # message:
        email_plaintext_message,
        # from:
        "noreply@somehost.local",
        # to:
        [reset_password_token.user.email]
    ) 

class User(AbstractUser):
   company_name = models.CharField(max_length=255, null=True, blank=True)
   aggrement = models.BooleanField(default=False, null=True, blank=True)
   country_code = models.CharField(max_length=5, null=True, blank=True)
   contact = models.CharField(max_length=15, null=True, blank=True)
   is_contact_verfication = models.BooleanField(default=False, null=True, blank=True)
   is_email_verfication = models.BooleanField(default=False, null=True, blank=True)
   otp = models.IntegerField(null=True, blank=True)
   otp_expiry_date = models.DateTimeField(null=True, blank=True)

class UserType(BaseContent):
   user = models.OneToOneField(User, on_delete=models.CASCADE)
   usertype = models.IntegerField(null=True, blank=True)

class BotRole(BaseContent):
   user = models.ForeignKey(User, on_delete=models.CASCADE)
   # bot = models.TextField(null=True, blank=True)
   role = models.CharField(max_length=300, null=True, blank=True)
   company = models.CharField(max_length=300, null=True, blank=True)
   name = models.CharField(max_length=300, null=True, blank=True)
   designation = models.CharField(max_length=300, null=True, blank=True)
   is_default = models.BooleanField(null=True, blank=True)

class TeamInvite(BaseContent):
   user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
   first_name = models.CharField(max_length=256, null=True, blank=True)
   last_name = models.CharField(max_length=256, null=True, blank=True)
   email = models.EmailField(null=True, blank=True)
   country_code = models.CharField(max_length=300, null=True, blank=True)
   contact = models.CharField(max_length=300, null=True, blank=True)
   expiration_date = models.DateTimeField(null=True,blank=True)
   is_accept = models.BooleanField(default=False)
   token = models.CharField(max_length=300, default=secrets.token_hex)

class AISecrateSetting(BaseContent):
   user = models.OneToOneField(User, on_delete=models.CASCADE)
   api_key = models.CharField(max_length=300, null=True, blank=True)
   is_verfied = models.BooleanField(default=False, null=True, blank=True)

class Language(BaseContent):
   language_name = models.CharField(max_length=300, null=True, blank=True)

class FontFamilyStyle(BaseContent):
   font_family = models.CharField(max_length=300, null=True, blank=True)

approve_choise=(
    ("in queue","in queue"),
    ("not in queue","not in queue"),
    ("message not found","message not found"),
    ("complete","complete"),
    ("failed","failed"),
    )

class Documents(BaseContent):
   user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
   role = models.ForeignKey(BotRole, on_delete=models.SET_NULL, null=True, blank=True)
   language = models.ForeignKey(Language, on_delete=models.SET_NULL, null=True, blank=True)
   name = models.CharField(max_length=300, null=True, blank=True)
   prompts = models.TextField(null=True, blank=True)
   maximum_token = models.BigIntegerField(null=True, blank=True)
   temperature = models.FloatField(null=True, blank=True)
   # status = models.BooleanField(default=False, null=True, blank=True)
   status = models.CharField(max_length=300, choices=approve_choise, null=True, blank=True, default="in queue")

class DocumentSetting_Header_Footer(BaseContent):
   user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
   header = models.BooleanField(default=False, null=True, blank=True)
   header_align = models.CharField(max_length=300, null=True, blank=True)
   header_logo = models.FileField(upload_to="Header_logo", null=True, blank=True)
   header_logo_size = models.IntegerField(null=True, blank=True)
   header_paragraph = models.TextField(null=True, blank=True)
   footer = models.BooleanField(default=False, null=True, blank=True)
   footer_align = models.CharField(max_length=300, null=True, blank=True)
   page_number = models.BooleanField(default=False, null=True, blank=True)
   skip_pages = models.BooleanField(default=False, null=True, blank=True)
   footer_paragraph = models.TextField(null=True, blank=True)

class DocumentSetting_Text_Setting(BaseContent):
   user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
   title = models.JSONField(null=True, blank=True)
   normal = models.JSONField(null=True, blank=True)
   h1 = models.JSONField(null=True, blank=True)
   h2 = models.JSONField(null=True, blank=True)
   h3 = models.JSONField(null=True, blank=True)
   h4 = models.JSONField(null=True, blank=True)
   h5 = models.JSONField(null=True, blank=True)
   h6 = models.JSONField(null=True, blank=True)
