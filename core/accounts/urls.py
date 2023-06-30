from django.urls import path
from .views import *

urlpatterns = [
    path('login/',LoginAPI.as_view(),name='login'),
    path('register/',RegistrationAPI.as_view(),name='register'),
    path('register/<int:id>',RegistrationAPI.as_view(),name='register'),
    path('changepassword/<int:id>',ChangePassword.as_view(),name='changepassword'),
 
    path('botroleapi/',BotRoleApi.as_view(),name='botroleapi'), # post
    path('botroleapi/<int:id>/',BotRoleApi.as_view(),name='botroleapi'),  #put get delete

    path('bulk-upload/',BulkInvitationAPI.as_view(),name='bulk_upload'),
    path('create-api/',ApiSettingAPI.as_view(),name='create_api'),
    path('delete-api/<int:id>',ApiSettingAPI.as_view(),name='delete_api'),

]