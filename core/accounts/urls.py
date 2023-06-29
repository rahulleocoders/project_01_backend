from django.urls import path
from .views import *

urlpatterns = [
    path('login/',LoginAPI.as_view(),name='login')
]