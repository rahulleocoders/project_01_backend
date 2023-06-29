from django.urls import path
from .views import *

urlpatterns = [
    path('login/',LoginAPI.as_view(),name='login'),
    path('register/',RegistrationAPI.as_view(),name='register'),
    path('otpverification/',OtpVerification.as_view(),name='otpverification'),

    path('botroleapi/',BotRoleApi.as_view(),name='botroleapi'),
    path('deleteuserbot/<int:id>/',DeleteUserBot.as_view(),name='deleteuserbot'),
    path('bulk-upload/',BulkInvitationAPI.as_view(),name='bulk_upload'),

]