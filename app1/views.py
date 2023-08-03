from rest_framework.views import APIView
from rest_framework.response import Response
from django.http import HttpResponse
import json
from app1.models import *
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken,AccessToken

from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
import re
from .serializer import UserSerializer, FileUploadSerializer
from django.contrib.auth import authenticate
import jwt, datetime
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth import *
import io
from rest_framework import generics
import io, csv, pandas as pd




class LoginAPI(APIView):
    """"This class is for LoginAPI"""
    def post(self , request):
        """"This method is for sending login credentials"""
        try:
            data = request.data
            email = data["email_id"]
            password = data["password"]
            
            user = authenticate(username=email, password=password)
            
            if user is None:
                return Response({
                    "msg": "User not found"
                }, status = status.HTTP_204_NO_CONTENT)
            
            refresh = RefreshToken.for_user(user)
            return Response({
                "refresh": str(refresh),
                "access": str(refresh.access_token)
            }, status=400)
        
        except Exception as err:
            return Response({
                "msg": "Something went wrong.",
                "error": str(err.args[0])
            }, status=status.HTTP_404_NOT_FOUND) 
            
            
 

class LogoutUser(APIView):
    """"This class is for LogoutAPI"""
    def post(self,request):
        """"This method is for sending logging out"""
        try:
            access_token = request.data.get("access")
            refresh_token = request.data.get("refresh")
            if refresh_token:
                # deleting the refresh token
                token = AccessToken(access_token)
                token.set_exp()
                t = RefreshToken(token=refresh_token)
                t.access_token.set_exp()
                return Response({"msg": "Logout successful"}, status=200)
            else:
                return Response({
                    "msg": "Invalid refresh token"
                }, status=400)
            
        except Exception as err:
            return Response({
                "msg": "Something went wrong.",
                "error": str(err.args[0])
            }, status=status.HTTP_400_BAD_REQUEST)





class UploadFileView(generics.CreateAPIView):
    serializer_class = FileUploadSerializer
    
    def post(self, request):
        try:
            file=request.FILES['data']
            if not file:
                return Response({
                            "message": "1something went wrong",
                            "error": str(err.args[0]),
                        },status=status.HTTP_400_BAD_REQUEST)  
            reader = pd.read_csv(file)
            

            for _, row in reader.iterrows():
                new_file = User(
                        # id = row['id'],
                        first_name= row["first_name"],
                        last_name= row['last_name'],
                        role_id= Role.objects.get(pk=row["role_id"]),
                        email_id= row["email_id"],
                        password = row["password"],
                        )
                
                new_file.save()
            


            return Response({"status": "success"},
                        status.HTTP_201_CREATED)
        except Exception as err:
            print(err)
            return Response({
                            "message": "2something went wrong",
                            "error": str(err.args[0]),
                        },status=status.HTTP_400_BAD_REQUEST)    
        
        # ghsdahgsdahgshgdajasdhsdaghdsgahdsagh
        
    def get(self,request):
            try:
                obj = User.objects.all()
                lst = []
                print("a")
                for obj_user in obj:

                    json_dict = {
                        "id": obj_user.id,
                        "first_name": obj_user.first_name,
                        "last_name": obj_user.last_name,
                        "role_id": obj_user.role_id.id,
                        "email_id": obj_user.email_id,
                        "created_at": obj_user.login_created_at,
                        "updated_at": obj_user.login_updated_at,
                        "deleted_at": obj_user.login_deleted_at,

                    }
                    
                    lst.append(json_dict)
                dff = pd.DataFrame(lst)
                
                print("df--->",dff)
                buff = io.StringIO()
                dff.to_csv(buff)
                data = buff.getvalue()
                buff.close()
                return Response(data=data,content_type='text/csv')

            except Exception as err:
                print(err)
                return Response({
                    "message": "Something went wrong",
                    "error": str(err.args[0])
                },status = status.HTTP_400_BAD_REQUEST)


    

        # serializer = self.get_serializer(data=request.data)
        # serializer.is_valid(raise_exception=True)
        # file = serializer.validated_data['file']
        # reader = pd.read_csv(file)
        # for _, row in reader.iterrows():
        #     new_file = User(
        #                id = row['id'],
        #                first_name= row["first_name"],
        #                last_name= row['last_name'],
        #                role_id= row["role_id"],
        #                email_id= row["email_id"],
        #                password = row["password"],
        #                )
        #     new_file.save()
        # return Response({"status": "success"},
        #                 status.HTTP_201_CREATED)




class UsersCreate(APIView): 
    """create the new user
    UserCreate or UserAPI"""

    authentication_classes = [JWTAuthentication]
    permission_classes  = [IsAuthenticated]



    def get(self, request,id=None):
        """  This method will show the details of particular user if id is present
         otherwise it will show details of all user """
        try:
            if id is not None:
                
                user = User.objects.get(pk = id)
                role_obj=Role.objects.get(pk=user.role_id.id)
                
                
                role_dict = {
                            "id": role_obj.id,
                            "role_name": role_obj.role_name,
                            "code": role_obj.code,
                            "created_at": role_obj.created_at,
                            "updated_at": role_obj.updated_at,
                            "deleted_at": role_obj.deleted_at,
                        }

                
                
                address_dict=[]
                address_all=Address.objects.filter(user_id=user)
                for address in address_all:
                    add_dict = {
                                "line": address.line,
                                "city": address.city,
                                "state": address.state,
                                "pincode": address.pincode,
                                "created_at": address.created_at,
                                "updated_at": address.updated_at,
                                "deleted_at": address.deleted_at,
                            }
                    address_dict.append(add_dict)
                

                json_dict = {
                            "id": user.id,
                            "first_name": user.first_name,
                            "last_name": user.last_name,
                            "role_id": role_dict,
                            "email_id": user.email_id,
                            "login_created_at": user.login_created_at,
                            "login_updated_at": user.login_updated_at,
                            "login_deleted_at": user.login_deleted_at,
                            "address":address_dict,
                        }

                return Response(json_dict, status=status.HTTP_200_OK)
            
            else:
            
                dict1=[]
                all_id=User.objects.all()
                for user in all_id:


                    role_obj=Role.objects.get(pk=user.role_id.id)
                    role_dict = {
                                "id": role_obj.id,
                                "role_name": role_obj.role_name,
                                "code": role_obj.code,
                                "created_at": role_obj.created_at,
                                "updated_at": role_obj.updated_at,
                                "deleted_at": role_obj.deleted_at,
                            }


                    address_dict=[]
                    address_all=Address.objects.filter(user_id=user)
                    for address in address_all:
                        add_dict = {
                            "line": address.line,
                            "city": address.city,
                            "state": address.state,
                            "pincode": address.pincode,
                            "created_at": address.created_at,
                            "updated_at": address.updated_at,
                            "deleted_at": address.deleted_at,
                        }
                        address_dict.append(add_dict)

                    json_dict = {
                                "id": user.id,
                                "first_name": user.first_name,
                                "last_name": user.last_name,
                                "role_id": role_dict,
                                "email_id": user.email_id,
                                "login_created_at": user.login_created_at,
                                "login_updated_at": user.login_updated_at,
                                "login_deleted_at": user.login_deleted_at,
                                "address":address_dict,
                            }
                    dict1.append(json_dict)
                return Response(dict1,status=status.HTTP_200_OK)
                


        except Exception as err:
            print(err)
            return Response({
                            "message": "something went wrong",
                            "error": str(err.args[0]),
                        },status=status.HTTP_400_BAD_REQUEST)    
        
        

    def post(self, request):
        """This method will enter the details of user """
        try:


            json_data=json.loads(request.body)

            user_data= User (first_name = request.data["first_name"],
                            last_name = request.data["last_name"],
                            role_id = Role.objects.get(pk=request.data["role_id"]),
                            email_id = request.data["email_id"],
                            password = request.data["password"],
                        )
            user_data.save()

            for address in json_data["address"]:
                address_data = Address(
                                    user_id = user_data,
                                    line = address.get("line"),
                                    city=address.get("city"),
                                    state=address.get("state"),
                                    pincode=address.get("pincode")
                                )

                address_data.save()

            return HttpResponse({
                 f"Employee Data with id {user_data.id} is created"
            },status=status.HTTP_201_CREATED)

        except Exception as err:
            print(err)
            return Response({
                            "message": "something went wrong in post",
                            "error": str(err.args[0])
                        },status=status.HTTP_400_BAD_REQUEST)
    

        
    def put(self, request,id=None):
        """"This method will update the details of particular user if id is present """
        try:

            json_data = json.loads(request.body)
            user = User.objects.get(pk = id)
            
            user.first_name = json_data["first_name"]
            user.last_name = json_data["last_name"]
            user.role_id = Role.objects.get(pk=request.data["role_id"])
            user.email_id = json_data["email_id"]
            user.password = json_data["password"]
            user.save()
            

            return Response({
                            "message" : f"Employee field with id {id} is updated successfully"
                        },status=status.HTTP_205_RESET_CONTENT)

        except Exception as err:
            print(err)
            return Response({
                            "message": f"something went wrong",
                            "error": str(err.args[0])
                        },status=status.HTTP_400_BAD_REQUEST)  
        
        
            



    def delete(self, request,id):
        """"This method will delete the details of particular user if id is present """
        try:
            user = User.objects.get(pk = id)
            user.delete()
            return Response({
                            "message":f"Employee with id {id} is deleted",
                        },status=status.HTTP_204_NO_CONTENT)

        except Exception as err:
            print(err)
            return Response({
                        "message": f"something went wrong",
                        "error": str(err.args[0])
                    },status=status.HTTP_400_BAD_REQUEST)
        

        
    def validation_get_emp_id(self, emp_id):
        try:
            User.objects.get(pk = emp_id)
            return True
        except:
            return False  
    
    
    
        



class RoleView(APIView):
    """"to create new role"""
    def get(self, request,id=None):

        """This method will show the details of particular role if id is present 
        otherwise it will show details of all roles"""

        try:
            if id is not None:
            
                role = Role.objects.get(pk = id)
                json_dict = {
                            "id": role.id,
                            "role_name": role.role_name,
                            "code": role.code,
                            "created_at": role.created_at,
                            "updated_at": role.updated_at,
                            "deleted_at": role.deleted_at,
                        }

                return Response(json_dict)
            
            else:
            
                dict1=[]
                all_id=Role.objects.all()
                for role in all_id:
                    json_dict = {
                                "id": role.id,
                                "role_name": role.role_name,
                                "code": role.code,
                                "created_at": role.created_at,
                                "updated_at": role.updated_at,
                                "deleted_at": role.deleted_at,
                            }
                    dict1.append(json_dict)
                return Response(dict1)
                


        except Exception as err:
            print(err)
            return Response({
                            "message": "something went wrong",
                            "error": str(err.args[0])
                        },status=status.HTTP_400_BAD_REQUEST)    
        
        

    def post(self, request):
        """This method will enter the details of role """
        try:
            json_data = json.loads(request.body)
            role_data= Role (role_name = json_data["role_name"],
                            code = json_data["code"])
            
            role_data.save()
            return HttpResponse({
                 f"Role data created with id {id}"
            })

        except Exception as err:
            print(err)
            return Response({
                            "message": "something went wrong in post",
                            "error": str(err.args[0])
                        },status=status.HTTP_400_BAD_REQUEST)
        
 
    def put(self, request,id=None):
        """"This method will update the details of particular role if id is present"""
        try:
            json_data = json.loads(request.body)
            role = Role.objects.get(pk = id)
            role.role_name = json_data["role_name"]
            role.code = json_data["code"]
            role.save()

            return Response({
                    "message" : f"Role field with id {id} is updated successfully"
                },status=status.HTTP_205_RESET_CONTENT)

        except Exception as err:
            print(err)
            return Response({
                            "message": f"something went wrong",
                            "error": str(err.args[0])
                        },status=status.HTTP_400_BAD_REQUEST)     



    
    def delete(self, request,id):
        """"This method will delete the details of particular user if id is present """
        try:
            
            role = Role.objects.get(pk = id)
            role.delete()
            return Response({
                            "message":f"Role with id {id} is deleted",
                        },status=status.HTTP_204_NO_CONTENT)

        except Exception as err:
            print(err)
            return Response({
                            "message": f"something went wrong",
                            "error": str(err.args[0])
                        },status=status.HTTP_400_BAD_REQUEST)
        

        
    def validation_get_emp_id(self, emp_id):
        try:
            User.objects.get(pk = emp_id)
            return True
        except:
            return False  
        


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
        
