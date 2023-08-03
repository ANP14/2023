from rest_framework import serializers

from .models import User


class LoginSerializer(serializers.Serializer):
    email=serializers.EmailField()
    password=serializers.CharField()


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model=User
        fields = ["id", "first_name", "last_name", "email_id", "password"]


class FileUploadSerializer(serializers.Serializer):
    file = serializers.FileField()