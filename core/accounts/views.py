from rest_framework.response import Response
from rest_framework.views import APIView
import json
from django.contrib.auth import authenticate,login,logout
from django.http import JsonResponse
from django.core import serializers as core_serializers
from django.views.decorators.csrf import csrf_exempt
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from django.utils.decorators import method_decorator
from django.contrib.auth.decorators import login_required
from rest_framework.parsers import MultiPartParser, FormParser
import os
from rest_framework import generics, status, permissions
from django.core.mail import send_mail, EmailMessage
from django.template.loader import render_to_string
from django.conf import settings
from django.urls import reverse
from django.contrib.sites.shortcuts import get_current_site
from django.shortcuts import render, redirect
from django.contrib.auth.models import update_last_login
from datetime import datetime, timedelta
from .util import *
from .models import *
from .serializer import *
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
import base64
from Cryptodome.Cipher import AES

# import jwt
# import uuid
# from rest_framework.permissions import IsAuthenticated
# import hashlib
# from django.contrib.auth.tokens import PasswordResetTokenGenerator
# from rest_framework.decorators import action
# from django.contrib.auth.hashers import check_password

key = '01234567890123456789015545678901'

def encrypt(key, plaintext):
    # Convert the key and plaintext to bytes
    key = key.encode('utf-8')
    plaintext = plaintext.encode('utf-8')
    # Generate a random initialization vector
    iv = os.urandom(16)
    # Create a new Cipher object
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Pad the plaintext to a multiple of 16 bytes
    padding_length = 16 - (len(plaintext) % 16)
    plaintext += bytes([padding_length]) * padding_length
    # Encrypt the plaintext and return the ciphertext and initialization vector
    ciphertext = cipher.encrypt(plaintext)
    return base64.b64encode(iv + ciphertext).decode('utf-8')

def decrypt(key, ciphertext):
    # Convert the key and ciphertext to bytes
    key = key.encode('utf-8')
    ciphertext = base64.b64decode(ciphertext.encode('utf-8'))
    # Extract the initialization vector
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    # Create a new Cipher object
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Decrypt the ciphertext and remove the padding
    plaintext = cipher.decrypt(ciphertext)
    padding_length = plaintext[-1]
    return plaintext[:-padding_length].decode('utf-8')

def get_user_usertype_userprofile(request,id):
    if User.objects.filter(id=id):
        user=User.objects.get(id=id)
        usertype=UserType.objects.get(user=user)
        return user,usertype
    else:
        return False,False

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

class RegistrationAPI(APIView):
    def post(self, request, format=None):
        first_name = request.data.get('first_name', '')
        last_name= request.data.get('last_name', '')
        email=request.data.get('email', '')
        country_code=request.data.get('country_code', '')
        contact=request.data.get('contact', '')
        company_name=request.data.get('company_name', '')
        password=request.data.get('password', '')
        conform_password=request.data.get('conform_password', '')
        aggrement=request.data.get('aggrement', '')
        if password == conform_password:
            userobj=User.objects.filter(username=email)
            if userobj:
                return Response(success(self,"User already exist with this email address"))
            else:
                userobj=User.objects.create(first_name=first_name, last_name=last_name, username=email, password=password,company_name=company_name,
                                            country_code=country_code,contact=contact,aggrement=aggrement)
                userobj.is_active =False
                userobj.is_contact_verfication = False
                userobj.is_email_verfication = False
                userobj.save()
                if TeamInvite.objects.filter(email = userobj.email):
                    usertypeobj = UserType.objects.create(user = userobj, usertype = 2)
                    team_page = False
                else:
                    usertypeobj = UserType.objects.create(user = userobj, usertype = 1)
                    team_page = True
                return Response(success(self,"Registration is successfull"))
        else:
            password != conform_password
            return Response(error(self,"Password is Not match"))


    def put(self, request,id=None):
        try:
            is_contact_verfication=request.data.get('is_contact_verfication','False')
            is_email_verfication=request.data.get('is_email_verfication','False')
            userobj=User.objects.get(id=id)
            userobj.is_contact_verfication=is_contact_verfication
            userobj.is_email_verfication=is_email_verfication
            userobj.is_active=True
            userobj.save()
            return Response(success(self,"OTP verified successfully"))
        except:
            return Response(error(self,"Invalid data"))

class ChangePassword(APIView):       
    def put(self,request, id=None):
        old_password = request.data.get('old_password','')
        new_password=request.data.get('new_password','')
        conform_password = request.data.get('conform_password','')
        if User.objects.filter(id=id):
            userobj=User.objects.get(id=id)
            userobj=authenticate(username=userobj.username,password=old_password)
            if userobj is not None:
                if new_password == conform_password:
                    userobj.set_password(new_password)
                    userobj.save()
                    return Response(success(self,"password updated"))
                else:
                    return Response(error(self,'Password and conform password Not Matched'))
            else:
                return Response(error(self,"User not found"))
        else:
            return Response(error(self,"Invalid data"))

class OtpVerification(APIView):
    def post(self, request):
        email=request.data.get('email','')
        contact=request.data.get('contact','')
        is_contact_verfication=request.data.get('is_contact_verfication','False')
        is_email_verfication=request.data.get('is_email_verfication','False')
        userobj=User.objects.update(username=email,contact=contact,is_contact_verfication=is_contact_verfication,
                                is_email_verfication=is_email_verfication)
        return Response(success(self,"OTP verified successfully"))

class LoginAPI(APIView):
    def post(self, request, format=None):
        try:
            data = request.data # {"emai":"yagnesh@yopmail.com","password":"1234"}
            if data['email'] is not None and data['password'] is not None:
                if User.objects.filter(username = data['email']): # checking
                    userobj = User.objects.get(username = data['email'])
                    user = authenticate(username = userobj.username, password = data['password'])
                    if user is not None:
                        token = get_tokens_for_user(user)
                        serializer = UserSerializer(user).data
                        usertype = UserType.objects.get(user = user)
                        context = {'user_datails':serializer, 'token':token, 'usertype':usertype.usertype}
                        return Response(success(self, context))
                    else:
                        return Response(error(self,'User Not Found'))
                else:
                    return Response(error(self,"Email is not valid"))
            else:
                return Response(error(self,"email and password are required"))
        except Exception as e:
            return Response(error(self,str(e)))

class BulkInvitationAPI(APIView):
    def post(self, request, format = None):
        try:
            data = request.data
            if data['user_id'] is not None and data['team_list'] is not None:
                user, usertype = get_user_usertype_userprofile(request, data['user_id'])
                if user:
                    user_emails = User.objects.values_list('username', flat=True)
                    team_emails = [team_member['email'] for team_member in data['team_list']]
                    remaining_emails = [email for email in team_emails if email not in user_emails]
                    if remaining_emails:
                        team_invite_emails = TeamInvite.objects.values_list('email', flat=True)
                        remaining_emails = [email for email in remaining_emails if email not in team_invite_emails]
                        if remaining_emails:
                            expiry_time = datetime.now() + timedelta(hours=3)
                            invites = []
                            for email_data in data['team_list']:
                                if email_data['email'] in remaining_emails:
                                    invite_obj = TeamInvite(
                                        user=user,
                                        first_name=email_data['first_name'],
                                        last_name=email_data['last_name'],
                                        email=email_data['email'],
                                        country_code=email_data['country_code'],
                                        contact=email_data['contact'],
                                        expiration_date=expiry_time
                                    )
                                    invites.append(invite_obj)
                            TeamInvite.objects.bulk_create(invites)
                            for invite_obj in invites:
                                uid = urlsafe_base64_encode(force_bytes(invite_obj.id))
                                absurl = 'http://127.0.0.1:8000/'
                                email_subject = 'Invitation to join our site'
                                email_body = render_to_string(
                                    'email_template.html',
                                    {'absurl': absurl, 'uid': uid, 'token': str(invite_obj.token)}
                                )
                                email = EmailMessage(
                                    email_subject,
                                    email_body,
                                    'invitations@example.com',
                                    [invite_obj.email]
                                )
                                email.send()

                            return Response({'message': 'Emails sent successfully'})
                    else:
                        return Response(self, "Email is already used")
                else:
                    return Response(error(self,'User Not Found'))
            else:
                return Response(error(self,"user_id and team_list are required"))
        except Exception as e:
            return Response(error(self,str(e)))

class ApiSettingAPI(APIView):
    def post(self, request, format = None):
        try:
            data = request.data
            if data['user_id'] is not None and data['API_Key'] is not None:
                user, usertype = get_user_usertype_userprofile(request, data['user_id'])
                if user:
                    encrypted_api = encrypt(key, data['API_Key'])
                    apiobj = AISecrateSetting.objects.create(
                        user = user, api_key = encrypted_api, is_verfied = True
                    )
                    serializer = AISecreateSerializer(apiobj).data
                    return Response(success(self, serializer))
                else:
                    return Response(error(self,'User Not Found'))
            else:
                return Response(error(self,"user_id and API_Key are required"))
        except Exception as e:
            return Response(error(self,str(e)))
    
    def delete(self, request, format = None, id=None):
        try:
            if id is not None:
                apiobj = AISecrateSetting.objects.get(id=id).delete()
                return Response(success(self,'Deleted Successfully'))
            else:
                return Response(error(self, "id is required"))
        except Exception as e:
            return Response(error(self,str(e)))

class BotRoleApi(APIView):
    def post(self,request,format=None):
        try:
            data=request.data
            if data['user_id'] is not None and data['bot'] is not None:
                user, usertype = get_user_usertype_userprofile(request, data['user_id'])
                if user:
                    botroleobj=BotRole.objects.create(user_id=user,bot=data['bot'])
                    return Response(success(self, "bot data created successfully"))
                else:
                    return Response(error(self, "User Not Found"))
            else:
                return Response(error(self, "user_id and bot is required"))
        except Exception as e:
            return Response(error(self,str(e)))

    def get(self, request, format=None, id=None):
        try:
            if id is not None:
                user, usertype = get_user_usertype_userprofile(request, id)
                if user:
                    bot_roles = BotRole.objects.filter(user = user)
                    serializer = BotRoleSerializer(bot_roles, many=True).data
                    if serializer:
                        return Response(success(self, serializer))
                    else:
                        return Response(error(self, 'Data not found'))
                else:
                    return Response(error(self, 'user not found'))
            else:
                return Response(error(self, 'id is required'))
        except Exception as e:
            return Response(error(self,str(e)))

    def delete(self, request, format=None, id=None):
        try:
            if id is not None:
                user_bot = BotRole.objects.get(id=id).delete()
                return Response(success(self, "BotRole deleted successfully."))
            else:
                return Response(error(self, "Invalid Data"))
        except Exception as e:
            return Response(error(self,str(e)))

    def put(self, request, format=None, id=None):
        try:
            if id is not None:
                bot_role = BotRole.objects.get(id=id)
                bot_role.bot = request.data.get('bot', None)
                bot_role.save()
                return Response(success(self, "Bot data updated successfully"))
            else:
                return Response(error(self, 'id is required'))
        except Exception as e:
            return Response(error(self,str(e)))
