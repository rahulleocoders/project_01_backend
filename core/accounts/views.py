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
from rest_framework.decorators import action
from django.contrib.auth.hashers import check_password

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


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

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
                        return Response(success(self, token))
                    else:
                        return Response(error(self,'User Not Found'))
                else:
                    return Response(error(self,"Email is not valid"))
            else:
                return Response(error(self,"Email and Password are required"))
        except Exception as e:
            return Response(error(self,str(e)))
        



