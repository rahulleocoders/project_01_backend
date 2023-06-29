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
class LoginAPI(APIView):
    def post(self, request, format=None):
        pass


class RegistrationAPI(APIView):
    def post(self, request, format=None):
        # first_name = request.data.get('first_name', '')
        # last_name= request.data.get('last_name', '')
        # email=request.data.get('email', '')
        # country_code=request.data.get('country_code', '')
        # contact=request.data.get('contact', '')
        # company_name=request.data.get('company_name', '')
        # password=request.data.get('password', '')
        # conform_password=request.data.get('conform_password', '')
        # aggrement=request.data.get('aggrement', '')

        # userobj=User.objects.create(first_name=first_name, last_name=last_name, email=email, password=password,conform_password=conform_password,company_name=company_name,
        #                             country_code=country_code,contact=contact,aggrement=aggrement)
        # print(userobj)
        return render(request, "yes")
        
