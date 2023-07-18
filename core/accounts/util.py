from rest_framework import status
from django.utils import timezone
import random
from datetime import datetime, timedelta
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.mail import EmailMessage
import threading
from . models import *
from django.template.loader import render_to_string
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from bs4 import BeautifulSoup

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

def otp_send(base,user):
    user_otp=random.randint(000000, 999999)
    now = timezone.now()
    expire_at = now + timedelta(minutes = 10)
    if User.objects.filter(email = user):
        userobj = User.objects.get(email = user)
        userobj.otp = user_otp
        userobj.otp_expiry_date = expire_at
        userobj.save()
        # uid = urlsafe_base64_encode(force_bytes(userobj.id))
        # absurl = 'http://127.0.0.1:8000/'
        email_subject = 'Invitation to join our site'
        email_body_html = render_to_string(
            'email_verfiaction.html',
            {"otp":user_otp}
        )

        soup = BeautifulSoup(email_body_html, 'html.parser')
        email_body_text = soup.get_text()

        soup = BeautifulSoup(email_body_html, 'html.parser')
        for tag in soup():
            tag.attrs["style"] = tag.get("style", "") + ";color: #000; font-family: 'Inter', sans-serif; font-size: 11px; font-weight: 600;"

        email_body_html = str(soup)

        email = EmailMessage(
            email_subject,
            email_body_text,
            'invitations@example.com',
            [userobj.email]
        )

        email.content_subtype = "html"
        email_status = email.send()
        return email_status