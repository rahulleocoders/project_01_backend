from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
import json
from django.contrib.auth import authenticate,login,logout
from django.http import JsonResponse
from django.core import serializers as core_serializers
from django.views.decorators.csrf import csrf_exempt
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework.permissions import IsAuthenticated
from django.utils.decorators import method_decorator
from django.contrib.auth.decorators import login_required
from rest_framework.parsers import MultiPartParser, FormParser
import os
import uuid
from rest_framework import generics, status, views, permissions
import jwt
from django.conf import settings
from django.urls import reverse 
from django.contrib.sites.shortcuts import get_current_site
from django.shortcuts import render, redirect
from django.contrib.auth.models import update_last_login
from datetime import date
from .models import User
from .util import *
from .models import *
from .serializer import *

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
                    emails = [team_member['email'] for team_member in data['team_list']]
                    
                    return Response("yess")
                else:
                    return Response(error(self,'User Not Found'))
            else:
                return Response(error(self,"user_id and team_list are required"))
        except Exception as e:
            return Response(error(self,str(e)))


class BotRoleApi(APIView):
    def post(self,request,format=None):
        try:
            data=request.data
            user_id=data.get('user_id',None)
            bot = data.get('bot', None)
            if user_id is not None:
                # userobj=User.objects.get(id=user_id)
                serializer=BotRole.objects.create(user_id=user_id,bot=bot)
                if serializer.is_valid():
                    serializer.save()
                return Response(success(self, serializer.data))
            else:
                return Response(error(self, "User Not Found"))
        except:
            return Response(error(self, "Invalid Data"))
        
class DeleteUserBot(APIView):
    def delete(self, request, format=None, id=None):
        try:
            if id is not None:
                user_bot = BotRole.objects.get(id=id)
                user_bot.delete()

                return Response(success(self, "BotRole deleted successfully."))
            else:
                return Response(error(self, "Invalid Data"))
        except Exception as e:
            return Response(error(self, f'Error: {str(e)}'))
        


