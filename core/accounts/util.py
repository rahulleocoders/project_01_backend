from rest_framework import status
from django.utils import timezone
import random
from datetime import datetime, timedelta
from rest_framework_simplejwt.tokens import RefreshToken

def success(self, msg):
    response = {
        "data":msg,
        "status" : "success",
        "code"   : status.HTTP_200_OK
    }
    return response

def error(self, msg):
    response = {
        "data":msg,
        "status" :"failed",
        "code"   : status.HTTP_400_BAD_REQUEST
    }
    return response