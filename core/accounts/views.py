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
                    print(emails)
                    return Response("yess")
                else:
                    return Response(error(self,'User Not Found'))
            else:
                return Response(error(self,"user_id and team_list are required"))
        except Exception as e:
            return Response(error(self,str(e)))