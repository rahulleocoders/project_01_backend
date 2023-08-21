from django.contrib import admin
from .models import *
import csv

@admin.register(User)
class User_Admin(admin.ModelAdmin):
    list_display = ['id','first_name','last_name','email','company_name','country_code','contact','is_contact_verfication','is_email_verfication']

@admin.register(UserType)
class UserType_Admin(admin.ModelAdmin):
    list_display = ['id','user','usertype']

@admin.register(TeamInvite)
class TeamInvite_Admin(admin.ModelAdmin):
    list_display = ['id', 'first_name', 'last_name', 'email', 'country_code', 'contact', 'expiration_date', 'is_accept']

@admin.register(Language)
class Admin_Language(admin.ModelAdmin):
    list_display = ["id", "language_name"]

@admin.register(BotRole)
class Admin_BotRole(admin.ModelAdmin):
    list_display = ["id", "user", "role", "company", "name", "designation", "is_default"]

@admin.register(AISecrateSetting)
class Admin_AISecrateSetting(admin.ModelAdmin):
    list_display = ["id", "user", "api_key", "is_verfied"]

@admin.register(Documents)
class Admin_Documents(admin.ModelAdmin):
    list_display = ["id", "user", "role", "language", "name", "prompts", "maximum_token", "temperature", "status"]

admin.site.register(DocumentSetting_Text_Setting)
admin.site.register(DocumentSetting_Header_Footer)