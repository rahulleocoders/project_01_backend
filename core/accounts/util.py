from rest_framework import status
from django.utils import timezone
import random
from datetime import datetime, timedelta
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.mail import EmailMessage
import threading

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

class EmailThread(threading.Thread):

    def __init__(self, email):
        self.email = email
        threading.Thread.__init__(self)

    def run(self):
        print("yes")
        self.email.send()
        
class Util:
    @staticmethod
    def send_email(data):
        email = EmailMessage(
            subject=data['email_subject'], body=data['email_body'], to=[data['to_email']])
        print(email)
        EmailThread(email).start()