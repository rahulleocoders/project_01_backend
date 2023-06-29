from rest_framework import serializers
from .models import *

class BotRoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = BotRole
        fields = "__all__"