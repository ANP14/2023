
from rest_framework.views import APIView
from rest_framework.response import Response
from django.http import HttpResponse
import json
from app1.models import *
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken

import re
from .serializer import UserSerializer
from django.contrib.auth import authenticate
import jwt, datetime
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth import *

class LoginAPI_cookies(APIView):
    """"This class is for LoginAPI"""
    def post(self , request):
        """"This method is for sending login credentials"""
        try:
            data = request.data
            email = data["email"]
            password = data["password"]
            user = User.objects.filter(email_id = email).first()
            if user is None:
                raise AuthenticationFailed('User not found')
            if password !=  user.password:
                raise AuthenticationFailed('User not found')
            refresh = RefreshToken.for_user(user)

            payload = {
                    'id': user.id,
                    'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
                    'iat': datetime.datetime.utcnow()
                    }

            token = jwt.encode(payload, 'secret', algorithm='HS256')

            response = Response(status=status.HTTP_201_CREATED)

            response.set_cookie(key='jwt', value=token, httponly=True)
            response.data = {
                    'jwt': token
                    }
            
            return (response)

        except Exception as err:
            print(err)
            return Response({
                            "message": "something went wrong",
                            "error": str(err.args[0]),
                        },status=status.HTTP_400_BAD_REQUEST)  
            
            
class Userview_cookies(APIView):
    """"This class is for viewing the User fields"""
    def get(self, request):
        """"This method is for getting User fields """
        try:
            token = request.COOKIES.get('jwt')
            if not token:
                raise AuthenticationFailed('Unauthenticated')
            try:
                payload = jwt.decode(token, 'secret', algorithms=['HS256'])
            except jwt.ExpiredSignatureError:
                raise AuthenticationFailed('Unauthenticated')
            user = User.objects.filter(id=payload['id']).first()
            serializer = UserSerializer(user)
            return Response(serializer.data, status=status.HTTP_200_OK)
   
        except Exception as err:
            print(err)
            return Response({
                        "message": "something went wrong",
                        "error": str(err.args[0]),
                    },status=status.HTTP_400_BAD_REQUEST)  

class LogoutUser_cookies(APIView):
    """"This class is for LogoutAPI"""
    def post(self,request):
        """"This method is for sending logging out"""
        try:
            response = Response(status=status.HTTP_204_NO_CONTENT)
            response.delete_cookie('jwt')
            response.data = {
                'message':'successfully logged out'
            }
            return response
        except Exception as err:
            print(err)
            return Response({
                        "message": "something went wrong",
                        "error": str(err.args[0]),
                    },status=status.HTTP_400_BAD_REQUEST)  
        
