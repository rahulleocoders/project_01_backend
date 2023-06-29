from django.contrib import admin
from .models import *

@admin.register(User)
class User_Admin(admin.ModelAdmin):
    list_display = ['id','first_name','last_name','email','company_name','country_code','contact','is_contact_verfication','is_email_verfication']

@admin.register(UserType)
class UserType_Admin(admin.ModelAdmin):
    list_display = ['id','user','usertype']