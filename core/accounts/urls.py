from django.urls import path
from .views import *

urlpatterns = [
    # Authothentication Login URL
    path('login/',LoginAPI.as_view(),name='login'),


    # Bulk Upload Team Memeber
    path('bulk-upload/',BulkInvitationAPI.as_view(),name='bulk_upload'),

]