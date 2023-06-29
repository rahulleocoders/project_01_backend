from django.db import models
from .basemodel import *
from django.contrib.auth.models import AbstractUser, User

class User(AbstractUser):
   company_name = models.CharField(max_length=255, null=True, blank=True)
   aggrement = models.BooleanField(default=False, null=True, blank=True)
   country_code = models.CharField(max_length=5, null=True, blank=True)
   contact = models.CharField(max_length=15, null=True, blank=True)
   is_contact_verfication = models.BooleanField(default=False, null=True, blank=True)
   is_email_verfication = models.BooleanField(default=False, null=True, blank=True)

class UserType(BaseContent):
   user = models.OneToOneField(User, on_delete=models.CASCADE)
   usertype = models.IntegerField(null=True, blank=True)

class BotRole(BaseContent):
   user = models.ForeignKey(User, on_delete=models.CASCADE)
   bot = models.TextField(null=True, blank=True)
   is_default = models.BooleanField(default=False, null=True, blank=True)

class TeamInvite(BaseContent):
   pass

class AISecrateSetting(BaseContent):
   user = models.OneToOneField(User, on_delete=models.CASCADE)
   api_key = models.CharField(max_length=300, null=True, blank=True)
   is_verfied = models.BooleanField(default=False, null=True, blank=True)