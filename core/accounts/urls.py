from django.urls import path
from .views import *

urlpatterns = [
    path('login/',LoginAPI.as_view(),name='login'),
    path('register/',RegistrationAPI.as_view(),name='register'),
    path('register/<int:id>',RegistrationAPI.as_view(),name='register'),
    path('changepassword/<int:id>',ChangePassword.as_view(),name='changepassword'),
 



]