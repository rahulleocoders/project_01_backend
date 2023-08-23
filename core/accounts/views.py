from rest_framework.response import Response
from rest_framework.views import APIView
from django.views import View
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
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework.permissions import IsAuthenticated
import base64
from Cryptodome.Cipher import AES
from tablib import Dataset
from django.db.models import Q
from accounts.paginatorviews import MyPagination

# import jwt
# import uuid
# import hashlib
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
        try:
            data = request.data
            if data['first_name'] is not None and data['last_name'] is not None and data['email'] is not None and data['country_code'] is not None and data['contact'] is not None and data['company_name'] is not None and data['password'] is not None and data['conform_password'] is not None:
                if data['password'] == data['conform_password']:
                    if User.objects.filter(email = data['email']):
                        return Response(error(self, 'Email is already in use'))
                    elif User.objects.filter(contact = data['contact']):
                        return Response(error(self, 'Contact is already in use'))
                    else:
                        userobj=User.objects.create_user(first_name = data['first_name'], last_name=data['last_name'], username=data['email'], email = data['email'], password = data['password'],company_name = data['company_name'], country_code = data['country_code'],contact=data['contact'],aggrement = data['aggrement'], is_active = False)

                        if TeamInvite.objects.filter(email = userobj.email):
                            usertypeobj = UserType.objects.create(user = userobj, usertype = 2)
                        else:
                            usertypeobj = UserType.objects.create(user = userobj, usertype = 1)
                        
                        email_status=otp_send(self,userobj)
                        print(email_status)
                        
                        return Response(success(self,{"msg":"Registration is successfull", "user":UserSerializer(userobj).data}))
                else:
                    return Response(error(self, 'Password not match'))
            else:
                return Response(error(self, 'first_name, last_name, email, country_code, contact, company_name, password, conform_password is required'))
        except Exception as e:
            return Response(error(self,str(e)))

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
        except Exception as e:
            return Response(error(self,str(e)))

class EmailOtpVerfication(APIView):
    def post(self, request):
        try:
            data = request.data
            if data['email'] != None and data['otp'] != None:
                if User.objects.filter(email = data['email']):
                    userobj = User.objects.get(email = data['email'])
                    now = timezone.now()
                    if(now > userobj.otp_expiry_date):
                        return Response(error(self, "OTP expired"))
                    else:
                        return Response(success(self,"Suceess"))
                else:
                    return Response(error(self, 'Inavalid email'))
            else:
                return Response(error(self, 'email and otp is required'))
        except Exception as e:
            return Response(error(self,str(e)))

class ProfileDataChange(APIView):
    def put(self, request, format = None):
        try:
            data = request.data
            if id is not None:
                user, usertype = get_user_usertype_userprofile(request, data["id"])
                if user:
                    user.contact = data.get("conatact")
                    user.email = data.get("email")
                    user.username = data.get("email")
                    user.save()
                    return Response(success(self,{"msg":"Updated is successfull", "user":UserSerializer(user).data}))
                else:
                    return Response(error(self,"Invalid User Profile"))
            else:
                return Response(error(self, 'id is required'))
        except Exception as e:
            return Response(error(self,str(e)))

class ChangePassword(APIView):       
    def put(self,request, id=None):
        try:
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
                    return Response(error(self,"Old Password is inccorect"))
            else:
                return Response(error(self,"Invalid User"))
        except Exception as e:
            return Response(error(self,str(e)))

class OtpVerification(APIView):
    def post(self, request):
        try:
            email=request.data.get('email','')
            contact=request.data.get('contact','')
            is_contact_verfication=request.data.get('is_contact_verfication','False')
            is_email_verfication=request.data.get('is_email_verfication','False')
            userobj=User.objects.update(username=email,contact=contact,is_contact_verfication=is_contact_verfication,
                                    is_email_verfication=is_email_verfication)
            return Response(success(self,"OTP verified successfully"))
        except Exception as e:
            return Response(error(self,str(e)))

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
    permission_classes= [IsAuthenticated]
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
                                current_site = get_current_site(request).domain
                                # absurl = 'http://{current_site}/' 
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

                            return Response(success(self,{'message': 'Emails sent successfully'}))
                    else:
                        return Response(error(self, "Email is already used"))
                else:
                    return Response(error(self,'User Not Found'))
            else:
                return Response(error(self,"user_id and team_list are required"))
        except Exception as e:
            return Response(error(self,str(e)))

    def get(self, request, format = None, id = None):
        try:
            if id is not None:
                user, usertype = get_user_usertype_userprofile(request, id)
                if user:
                    invite_obj = TeamInvite.objects.filter(user=user)
                    serializer = TeamInviteSerializer(invite_obj, many=True)
                    if serializer.data:
                        return Response(success(self, serializer.data))
                    else:
                        return Response(error(self, "Data Not Found"))
                else:
                    return Response(error(self, "Invalid user"))
            else:
                return Response(error(self, 'Id is required'))
        except Exception as e:
            return Response(error(self,str(e)))
    
    def delete(self, request, format = None, id = None):
        try:
            if id is not None:
                invite_obj = TeamInvite.objects.get(id=id).delete()
                return Response(success(self, 'Deleted Data Successfully'))
            else:
                return Response(error(self, 'Id is required'))
        except Exception as e:
            return Response(error(self,str(e)))

class ApiSettingAPI(APIView):
    permission_classes= [IsAuthenticated]
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
                    if serializer:
                        return Response(success(self, serializer))
                    else:
                        return Response(error(self, "Data not Found"))
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
    permission_classes= [IsAuthenticated]
    def post(self,request,format=None):
        try:
            data=request.data
            if data['user_id'] is not None and data['role'] is not None and data['company'] is not None and data['name'] is not None and data['designation'] is not None:
                user, usertype = get_user_usertype_userprofile(request, data['user_id'])
                if user:
                    botroleobj=BotRole.objects.create(user_id=user.id,role=data['role'], company = data['company'], name = data['name'], designation = data['designation'], is_default = False)
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
                    bot_roles = BotRole.objects.filter(user = user).order_by("-id")
                    print(bot_roles)
                    serializer = BotRoleSerializer(bot_roles, many=True)
                    if serializer.data:
                        return Response(success(self, serializer.data))
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
                bot_role.role = request.data.get('role', None)
                bot_role.company = request.data.get('company', None)
                bot_role.name = request.data.get('name', None)
                bot_role.designation = request.data.get('designation', None)
                bot_role.save()
                return Response(success(self, "Bot data updated successfully"))
            else:
                return Response(error(self, 'id is required'))
        except Exception as e:
            return Response(error(self,str(e)))

class GetData_BotRole(APIView):
    permission_classes= [IsAuthenticated]
    def get(self, request, format=None, id = None):
        try:
            if id is not None:
                botroleobj=BotRole.objects.get(id = id)
                serializer = BotRoleSerializer(botroleobj)
                if serializer.data:
                    return Response(success(self, serializer))
                else:
                    return Response(error(self, 'Data not found'))
            else:
                return Response(error(self, 'id is required'))
        except Exception as e:
            return Response(error(self,str(e)))

# Set Deafult
class Set_Default_Bot_Role(APIView):
    permission_classes= [IsAuthenticated]
    def get(self, request, format=None, id=None):
        try:
            if id is not None:
                user_id = request.GET.get('user')
                user, usertype = get_user_usertype_userprofile(request, user_id)
                if BotRole.objects.filter(user = user, is_default = True):
                    bot = BotRole.objects.filter(user = user).get(is_default = True)
                    bot.is_default = False
                    bot.save()
                botroleobj=BotRole.objects.get(id = id)
                botroleobj.is_default = True
                botroleobj.save()
                return Response(success(self, "Bot role updated successfully"))
            else:
                return Response(error(self, 'id is required'))
        except Exception as e:
            return Response(error(self,str(e)))

# Language
class AdminLangaugeAdd(APIView):
    def post(self, request, format=None):
        try:
            dataset = Dataset()
            file = request.FILES['myfile']
            imported_data = dataset.load(file.read(),format='xlsx')
            for data in imported_data:
                value = Language.objects.get_or_create(language_name=data[0]) 
            return Response(success(self,"Successfully imported"))
        except Exception as e:
            return Response(error(self,str(e)))
        
# Font Family
class AdminFontAdd(APIView):
    def post(self, request, format=None):
        try:
            dataset = Dataset()
            file = request.FILES['myfile']
            imported_data = dataset.load(file.read(),format='xlsx')
            for data in imported_data:
                value = FontFamilyStyle.objects.get_or_create(font_family=data[0]) 
            return Response(success(self,"Successfully imported"))
        except Exception as e:
            return Response(error(self,str(e)))

class SearchFont(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request, format=None):
        try:
            font_obj = FontFamilyStyle.objects.all()
            paginator = MyPagination()
            paginated_queryset = paginator.paginate_queryset(font_obj, request)
            serializer = Font_Family_Serializer(paginated_queryset, many = True)
            if serializer.data:
                return Response(success(self, serializer.data))
            else:
                return Response(error(self, "Data Not Found"))
        except Exception as e:
            return Response(error(self,str(e)))
        
    def post(self, request, fromat = None):
        try:
            search = request.data.get('search')
            if search:
                font_family = Q(font_family__startswith = search)
                font_family_obj = FontFamilyStyle.objects.filter(font_family)
                paginator = MyPagination()
                paginated_queryset = paginator.paginate_queryset(font_family_obj, request)
                serializer = Font_Family_Serializer(paginated_queryset, many = True)
                if serializer.data:
                    return Response(success(self, serializer.data))
                else:
                    return Response(error(self, "Data Not Found"))
            else:
                return Response(error(self, "search is required"))
        except Exception as e:
            return Response(error(self,str(e)))

class SearchLangauge(APIView):
    permission_classes= [IsAuthenticated]
    def get(self, request, format=None):
        try:
            language_obj = Language.objects.all()
            serializer = LanguageSerializer(language_obj, many = True)
            if serializer.data:
                return Response(success(self, serializer.data))
            else:
                return Response(error(self, "Data not found"))
        except Exception as e:
            return Response(error(self,str(e)))
    
    def post(self, request, fromat= None):
        try:
            search = request.data.get('search')
            if search:
                language = Q(language_name__startswith = search)
                language_obj = Language.objects.filter(language)
                serializer = LanguageSerializer(language_obj, many = True)
                if serializer.data:
                    return Response(success(self, serializer.data))
                else:
                    return Response(error(self, "Data not found"))
            else:
                return Response(error(self, "search is required"))
        except Exception as e:
            return Response(error(self,str(e)))

class ForgetPassword(APIView):
    def post(self, request, format = None):
        try:
            email = request.data.get("email")
            if email:
                if User.objects.filter(email=email):
                    user = User.objects.get(email=email)
                    uid = urlsafe_base64_encode(force_bytes(user.id))
                    token = PasswordResetTokenGenerator().make_token(user)
                    absurl = settings.SITE_URL+'/reset-password/'+"?uid="+uid+'&'+"token="+token
                    email_body = 'Hi '+user.email + \
                    ' Use the link below to reset your password \n' + absurl
                    data = {'email_body': email_body, 'to_email': user.email,'email_subject': 'Verify your email'}
                    Util.send_email(data)
                    return Response(success(self,'Email Sent Successfull'))
                else:
                    return Response(error(self,'User Not Found'))
            else:
                return Response(error(self, "email is required"))
        except Exception as e:
            return Response(error(self,str(e)))

class ResetPassword(APIView):
    def post(self, request, format=None):
        try:
            uid = request.data.get('uid')
            token = request.data.get('token')
            password = request.data.get('password')
            cnf_password = request.data.get('cnf_password')
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)
            if password and cnf_password != None:
                if password != cnf_password:
                    return Response(error(self, "Password and Confirm Password doesn't match"))
                if not PasswordResetTokenGenerator().check_token(user, token):
                    return Response(error(self,'Token is not Valid or Expired'))
                user.set_password(password)
                user.save()
                return Response(success(self,'Password Updated Successfully'))
            else:
                return Response(error(self,'password and password1 is required'))
        except Exception as e:
            return Response(error(self,str(e)))

class DocumnetsAPI(APIView):
    permission_classes= [IsAuthenticated]
    def post(self, request, format=None):
        try:
            user_obj = request.data.get('user')
            role = request.data.get('role')
            language = request.data.get('language')
            name = request.data.get('name')
            prompts = request.data.get('prompts')
            maximum_token = request.data.get('maximum_token')
            temperature = request.data.get('temperature')
            user, usertype = get_user_usertype_userprofile(request, user_obj)
            if user:
                role_obj = BotRole.objects.get(id = role)
                language_obj = Language.objects.get(id = language)
                documents_obj = Documents.objects.create(
                    user = user, role = role_obj, language = language_obj, name = name, prompts = prompts, maximum_token = int(maximum_token), temperature = int(temperature)
                )
                return Response(success(self, 'Successfully Created'))
            else:
                return Response(error(self,'User Not Found'))
        except Exception as e:
            return Response(error(self,str(e)))
    
    def get(self, request, format = None, id = None):
        try:
            if id is not None:
                user, usertype = get_user_usertype_userprofile(request, id)
                if user:
                    documents_obj = Documents.objects.filter(user = user)
                    serializer = DocumentSerializer(documents_obj, many=True)
                    if serializer.data:
                        return Response(success(self, serializer.data))
                    else:
                        return Response(error(self, "Data Not Found"))
                else:
                    return Response(error(self,'User Not Found'))
            else:
                return Response(error(self,'id is required'))
        except Exception as e:
            return Response(error(self,str(e)))
        
    def delete(self, request, format = None, id = None):
        try:
            if id is not None:
                documents_obj = Documents.objects.get(id = id).delete()
                return Response(success(self, 'Deleted Document Successfully'))
            else:
                return Response(error(self,'id is required'))
        except Exception as e:
            return Response(error(self,str(e)))
    
    def put(self, request, format = None, id = None):
        try:
            if id is not None:
                documents_obj = Documents.objects.get(id = id)
                documents_obj.role = BotRole.objects.get(id = request.data.get('role'))
                documents_obj.language = Language.objects.get(id = request.data.get('language'))
                documents_obj.name = request.data.get('name')
                documents_obj.prompts = request.data.get('prompts')
                documents_obj.maximum_token = request.data.get('maximum_token')
                documents_obj.temperature = request.data.get('temperature')
                documents_obj.save()
                return Response(success(self, "Documents updated successfully"))
            else:
                return Response(error(self,'id is required'))
        except Exception as e:
            return Response(error(self,str(e)))

class PromptsAPI(APIView):
    permission_classes= [IsAuthenticated]
    def get(self, request, format = None, id = None):
        try:
            if id is not None:
                user, usertype = get_user_usertype_userprofile(request, id)
                if user:
                    documents_obj = Documents.objects.filter(user = user)
                    serializer = Propts_Serializer(documents_obj, many=True)
                    if serializer.data:
                        return Response(success(self, serializer.data))
                    else:
                        return Response(error(self, "Data Not Found"))
                else:
                    return Response(error(self,'User Not Found'))
            else:
                return Response(error(self,'id is required'))
        except Exception as e:
            return Response(error(self,str(e)))

class GetDocumentsAPI(APIView):
    permission_classes= [IsAuthenticated]
    def get(self, request, format = None, id = None):
        try:
            if id is not None:
                documents_obj = Documents.objects.get(id = id)
                serializer = GetDocumentsSerializer(documents_obj)
                if serializer.data:
                    return Response(success(self, serializer.data))
                else:
                    return Response(error(self, "Data not found"))
            else:
                return Response(error(self,'id is required'))
        except Exception as e:
            return Response(error(self,str(e)))

class GetDoucmentsCount(APIView):
    permission_classes= [IsAuthenticated]
    def get(self, request, format = None, id = None):
        try:
            if id is not None:
                user, usertype = get_user_usertype_userprofile(request, id)
                if user:
                    all_documents = Documents.objects.filter(user = user).count()
                    in_progress = Documents.objects.filter(user = user).filter(status = False).count()
                    complete = Documents.objects.filter(user = user).filter(status = True).count()
                    return Response(success(self, {"all_documents": all_documents, "in_progress": in_progress, "complete": complete}))
                else:
                    return Response(error(self,'User Not Found'))
            else:
                return Response(error(self,'id is required'))
        except Exception as e:
            return Response(error(self,str(e)))

class Header_Document(APIView):
    permission_classes= [IsAuthenticated]
    def post(self, request, format = None):
        try:
            user_id = request.POST.get('user')
            header = request.POST.get('header')
            header_align = request.POST.get('header_align')
            header_logo = request.FILES.get('header_logo')
            header_logo_size = request.POST.get('header_logo_size')
            header_paragraph = request.POST.get('header_paragraph')
            user, usertype = get_user_usertype_userprofile(request, user_id)
            if user:
                header_obj, created = DocumentSetting_Header_Footer.objects.get_or_create(user = user)
                if not created:
                    header_obj.header = header
                    header_obj.header_align = header_align
                    if header_logo:
                        header_obj.header_logo = header_logo
                    else:
                        pass
                    header_obj.header_logo_size = header_logo_size
                    header_obj.header_paragraph = header_paragraph
                    header_obj.save()
                else:
                    header_obj.header = header
                    header_obj.header_align = header_align
                    if header_logo:
                        header_obj.header_logo = header_logo
                    else:
                        pass
                    header_obj.header_logo_size = header_logo_size
                    header_obj.header_paragraph = header_paragraph
                    header_obj.save()
                return Response(success(self, "Successfully created"))
            else:
                return Response(error(self,'User Not Found'))
        except Exception as e:
            return Response(error(self,str(e)))
        
    def get(self, request, format=None, id = None):
        try:
            if id is not None:
                user, usertype = get_user_usertype_userprofile(request, id)
                if user:
                    header_obj = DocumentSetting_Header_Footer.objects.get(user = user)
                    serializer = Header_Serializer(header_obj)
                    if serializer.data:
                        return Response(success(self, serializer.data))
                    else:
                        return Response(error(self,"Data Not Found"))
                else:
                    return Response(error(self,'User Not Found'))
            else:
                return Response(error(self,'id is required'))
        except Exception as e:
            return Response(error(self,str(e)))

class Footer_Documents(APIView):
    def post(self, request, format = None):
        try:
            user_id = request.POST.get('user')
            footer = request.POST.get('footer')
            footer_align = request.POST.get('footer_align')
            page_number = request.POST.get('page_number')
            skip_pages = request.POST.get('skip_pages')
            footer_paragraph = request.POST.get('footer_paragraph')
            user, usertype = get_user_usertype_userprofile(request, user_id)
            if user:
                footer_obj, created = DocumentSetting_Header_Footer.objects.get_or_create(user = user)
                if not created:
                    footer_obj.footer = footer
                    footer_obj.footer_align = footer_align
                    footer_obj.page_number = page_number
                    footer_obj.skip_pages = skip_pages
                    footer_obj.footer_paragraph = footer_paragraph
                    footer_obj.save()
                else:
                    footer_obj.footer = footer
                    footer_obj.footer_align = footer_align
                    footer_obj.page_number = page_number
                    footer_obj.skip_pages = skip_pages
                    footer_obj.footer_paragraph = footer_paragraph
                    footer_obj.save()
                return Response(success(self, "Successfully created"))
            else:
                return Response(error(self,'User Not Found'))
        except Exception as e:
            return Response(error(self,str(e)))
    
    def get(self, request, format=None, id = None):
        try:
            if id is not None:
                user, usertype = get_user_usertype_userprofile(request, id)
                if user:
                    footer_obj = DocumentSetting_Header_Footer.objects.get(user = user)
                    serializer = Footer_Serializer(footer_obj)
                    if serializer.data:
                        return Response(success(self, serializer.data))
                    else:
                        return Response(error(self,"Data Not Found"))
                else:
                    return Response(error(self,'User Not Found'))
            else:
                return Response(error(self,'id is required'))
        except Exception as e:
            return Response(error(self,str(e)))

# class Header_Foorter_Document(APIView):
#     permission_classes= [IsAuthenticated]
#     def post(self, request, format = None):
#         try:
#             user_id = request.POST.get('user')
#             header = request.POST.get('header')
#             header_align = request.POST.get('header_align')
#             header_logo = request.FILES.get('header_logo')
#             header_logo_size = request.POST.get('header_logo_size')
#             header_paragraph = request.POST.get('header_paragraph')
#             footer = request.POST.get('footer')
#             footer_align = request.POST.get('footer_align')
#             page_number = request.POST.get('page_number')
#             skip_pages = request.POST.get('skip_pages')
#             footer_paragraph = request.POST.get('footer_paragraph')
#             user, usertype = get_user_usertype_userprofile(request, user_id)
#             if user:
#                 if DocumentSetting_Header_Footer.objects.filter(user = user):
#                     header_footer_obj = DocumentSetting_Header_Footer.objects.get(user = user)
#                     header_footer_obj.header = header
#                     header_footer_obj.header_align = header_align
#                     if header_logo:
#                         header_footer_obj.header_logo = header_logo
#                     else:
#                         pass
#                     header_footer_obj.header_logo_size = header_logo_size
#                     header_footer_obj.header_paragraph = header_paragraph
#                     header_footer_obj.footer = footer
#                     header_footer_obj.footer_align = footer_align
#                     header_footer_obj.page_number = page_number
#                     header_footer_obj.skip_pages = skip_pages
#                     header_footer_obj.footer_paragraph = footer_paragraph
#                     header_footer_obj.save()
#                     return Response(success(self, 'Successfully updated'))
#                 else:
#                     header_footer_obj = DocumentSetting_Header_Footer.objects.create(
#                         user = user, header = header, header_align = header_align, header_logo = header_logo, header_logo_size = header_logo_size, header_paragraph = header_paragraph, footer = footer, footer_align = footer_align, page_number = page_number, skip_pages = skip_pages, footer_paragraph = footer_paragraph
#                     )
#                     return Response(success(self, 'Successfully created'))
#             else:
#                 return Response(error(self,'User Not Found'))
#         except Exception as e:
#             return Response(error(self,str(e)))
    
#     def get(self, request, format=None, id = None):
#         try:
#             if id is not None:
#                 user, usertype = get_user_usertype_userprofile(request, id)
#                 if user:
#                     header_footer_obj = DocumentSetting_Header_Footer.objects.get(user = user)
#                     serializer = Header_Footer_Serializer(header_footer_obj)
#                     if serializer.data:
#                         return Response(success(self, serializer.data))
#                     else:
#                         return Response(error(self,"Data Not Found"))
#                 else:
#                     return Response(error(self,'User Not Found'))
#             else:
#                 return Response(error(self,'id is required'))
#         except Exception as e:
#             return Response(error(self,str(e)))

class Text_Setting_Documents(APIView):
    permission_classes= [IsAuthenticated]
    def post(self, request, format = None):
        try:
            user_id = request.data.get('user')
            titles = request.data.get('titles')
            normal = request.data.get('normal')
            h1 = request.data.get('h1')
            h2 = request.data.get('h2')
            h3 = request.data.get('h3')
            h4 = request.data.get('h4')
            h5 = request.data.get('h5')
            h6 = request.data.get('h6')
            user, usertype = get_user_usertype_userprofile(request, user_id)
            if user:
                text_settings, created = DocumentSetting_Text_Setting.objects.get_or_create(user=user)
                if not created:
                    # Update existing text settings
                    text_settings.title = titles
                    text_settings.normal = normal
                    text_settings.h1 = h1
                    text_settings.h2 = h2
                    text_settings.h3 = h3
                    text_settings.h4 = h4
                    text_settings.h5 = h5
                    text_settings.h6 = h6
                    text_settings.save()
                    return Response(success(self, "Successfully updated"))
                else:
                    # Create new text settings
                    text_settings.title = titles
                    text_settings.normal = normal
                    text_settings.h1 = h1
                    text_settings.h2 = h2
                    text_settings.h3 = h3
                    text_settings.h4 = h4
                    text_settings.h5 = h5
                    text_settings.h6 = h6
                    text_settings.save()
                    return Response(success(self, "Successfully created"))
            else:
                return Response(error(self,'User Not Found'))
        except Exception as e:
            return Response(error(self,str(e)))

    def get(self, request, format = None, id = None):
        try:
            if id is not None:
                user, usertype = get_user_usertype_userprofile(request, id)
                if user:
                    text_obj = DocumentSetting_Text_Setting.objects.filter(user = user)
                    serializer = Text_Setting_Serializer(text_obj, many=True)
                    if serializer.data:
                        return Response(success(self, serializer.data))
                    else:
                        return Response(error(self, 'Data not found'))
                else:
                    return Response(error(self,'User Not Found'))
            else:
                return Response(error(self, "id is required"))
        except Exception as e:
            return Response(error(self,str(e)))

