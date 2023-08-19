from django.urls import path
from .views import *

urlpatterns = [
    path('login/',LoginAPI.as_view(),name='login'),
    path('register/',RegistrationAPI.as_view(),name='register'),
    path('register/<int:id>',RegistrationAPI.as_view(),name='register'),

    path('profile-data-change/',ProfileDataChange.as_view(),name='profile-data-change'),

    path('email-otp-verfication/',EmailOtpVerfication.as_view(),name='email-otp-verfication'),

    path('changepassword/<int:id>',ChangePassword.as_view(),name='changepassword'),
 
    path('botroleapi/',BotRoleApi.as_view(),name='botroleapi'), # post
    path('botroleapi/<int:id>/',BotRoleApi.as_view(),name='botroleapi'),  #put get delete

    path('bulk-upload/',BulkInvitationAPI.as_view(),name='bulk_upload'),
    path('bulk-upload/<int:id>',BulkInvitationAPI.as_view(),name='bulk_upload'),
    path('create-api/',ApiSettingAPI.as_view(),name='create_api'),
    path('delete-api/<int:id>',ApiSettingAPI.as_view(),name='delete_api'),
    
    path('Langauge-add/',AdminLangaugeAdd.as_view(),name='Langauge_add'),
    path('Langauge-list/',SearchLangauge.as_view(),name='Langauge_list'),

    path('forget-password/',ForgetPassword.as_view(),name='forget_password'),
    path('reset-password/',ResetPassword.as_view(),name='reset_password'),

]
