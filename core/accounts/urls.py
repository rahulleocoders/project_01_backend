from django.urls import path
from .views import *

urlpatterns = [
    path('login/',LoginAPI.as_view(),name='login'),
    path('botroleapi/',BotRoleApi.as_view(),name='botroleapi'),
    path('deleteuserbot/<int:id>/',DeleteUserBot.as_view(),name='deleteuserbot'),

]