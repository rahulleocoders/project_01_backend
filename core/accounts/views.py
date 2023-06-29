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


class RegistrationAPI(APIView):
    def post(self, request, format=None):
        first_name = request.data.get('first_name', '')
        last_name= request.data.get('last_name', '')
        email=request.data.get('email', '')
        country_code=request.data.get('country_code', '')
        contact=request.data.get('contact', '')
        company_name=request.data.get('company_name', '')
        password=request.data.get('password', '')
        # conform_password=request.data.get('conform_password', '')
        aggrement=request.data.get('aggrement', '')
        userobj=User.objects.filter(email=email)
        if userobj:
            return Response(success(self,"User already exist with this email address"))
        else:
            userobj=User.objects.create(username=first_name, last_name=last_name, email=email, password=password,company_name=company_name,
                                        country_code=country_code,contact=contact,aggrement=aggrement)
            print(userobj)
            return Response(success(self,"Registration is successfull"))
                   
        

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
