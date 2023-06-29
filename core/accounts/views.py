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
from .serializers import *

class LoginAPI(APIView):
    def post(self, request, format=None):
        try:
            data = request.data # {"emai":"yagnesh@yopmail.com","password":"1234"}
            if data['email'] is not None and data['password'] is not None:
                if User.objects.filter(username = data['email']): # checking
                    user = User.objects.get(username = data['email'])
                    print(user)
                    return Response("yess")
                else:
                    return Response(error(self,"Email is not valid"))
            else:
                return Response(error(self,"Email and Password are required"))
        except Exception as e:
            return Response(error(self,str(e)))


class BotRoleApi(APIView):
    def post(self,request,format=None):
        try:
            data=request.data
            user_id=data.get('user_id',None)
            bot = data.get('bot', None)
            if user_id is not None:
                botroleobj=BotRole.objects.create(user_id=user_id,bot=bot)
                botroleobj.save()

                return Response(success(self, "bot data created successfully"))
            else:
                return Response(error(self, "User Not Found"))
        except:
                return Response(error(self, "Invalid Data"))
        
    
    def get(self, request, format=None):
        try:
            bot_roles = BotRole.objects.all()
            serializer = BotRoleSerializer(bot_roles, many=True)
            return Response(success(self, serializer.data))
        except:
            return Response(error(self, "Data Not Found"))

    
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
      
            

    def put(self, request, format=None):
        try:
            data = request.data
            bot_id = data.get('bot_id', None)
            bot = data.get('bot', None)
            if bot_id is not None:
                    bot_role = BotRole.objects.get(id=bot_id)
                    bot_role.bot = bot
                    bot_role.save()
                    return Response(success(self, "Bot data updated successfully"))
                
            else:
                return Response(error(self, "Bot ID Not Found"))
        except:
            return Response(error(self, "Invalid Data"))
        


