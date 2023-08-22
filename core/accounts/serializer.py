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

class TeamInviteSerializer(serializers.ModelSerializer):
    class Meta:
        model = TeamInvite
        fields = ["id","first_name","last_name","email","country_code","contact","is_accept"]

class LanguageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Language
        fields = "__all__"

class DocumentSerializer(serializers.ModelSerializer):
    user = serializers.SerializerMethodField()
    role = serializers.SerializerMethodField()
    language = serializers.SerializerMethodField()
    class Meta:
        model = Documents
        fields = "__all__"
    
    def get_user(self, obj):
        user = User.objects.get(id = obj.user.id)
        name = str(user.first_name +" "+ user.last_name)
        return name
    
    def get_role(self, obj):
        role = BotRole.objects.get(id = obj.role.id)
        serializer = BotRoleSerializer(role)
        return serializer.data

    def get_language(self, obj):
        language = Language.objects.get(id = obj.language.id)
        return language.language_name

class GetDocumentsSerializer(serializers.ModelSerializer):
    role = BotRoleSerializer()
    language = LanguageSerializer()
    class Meta:
        model = Documents
        fields = "__all__"

class Header_Footer_Serializer(serializers.ModelSerializer):
    class Meta:
        model = DocumentSetting_Header_Footer
        fields = "__all__"

class Text_Setting_Serializer(serializers.ModelSerializer):
    class Meta:
        model = DocumentSetting_Text_Setting
        fields = "__all__"

class Propts_Serializer(serializers.ModelSerializer):
    user = serializers.SerializerMethodField()
    class Meta:
        model = Documents
        fields = ["id","user","name","prompts","status","created_on","last_modified"]
    
    def get_user(self, obj):
        user = User.objects.get(id = obj.user.id)
        name = str(user.first_name +" "+ user.last_name)
        return name