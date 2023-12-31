from rest_framework import serializers
from .models import *

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id','first_name','last_name','email','company_name','country_code','contact','is_contact_verfication','is_email_verfication']

class AISecreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = AISecrateSetting
        fields = "__all__"

class BotRoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = BotRole
        fields = "__all__"
