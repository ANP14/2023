from django.db import models
from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
import re
from django.contrib.auth.models import AbstractUser

# validating the name if it contains special characters then raise error
def validate_name( value):
    regex =re.compile('[@_!#$%^&*()<>?/|}{~:]')
    if(regex.search(value) == None):
        return value
    else:
        raise ValidationError("This field does not accepts Special characters")
    


# Create your models here.

class Role(models.Model):
    id =   models.AutoField( primary_key=True, db_column="role_id") # primary key and not null
    role_name = models.CharField( max_length=50, null=False) # not null
    code = models.CharField(max_length=20,  validators =[validate_name])
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)
    deleted_at = models.DateTimeField(blank=True, null=True)  



    def __str__(self):
        return f"{self.id}--{self.role_name}"


    
class User(models.Model):
    id =   models.AutoField(primary_key=True) 
    first_name = models.CharField( max_length=50, null=False, validators =[validate_name]) # not null
    last_name = models.CharField( max_length=50, validators =[validate_name])
    role_id =   models.ForeignKey(Role, on_delete=models.CASCADE, null=True)
    email_id = models.EmailField()
    password = models.TextField()
    login_created_at = models.DateTimeField(auto_now_add=True)
    login_updated_at = models.DateTimeField(auto_now=True, null=True)
    login_deleted_at = models.DateTimeField(blank=True, null=True)  
    
    
    def __str__(self):
        return f"{self.first_name}--{self.last_name}"    




class Address(models.Model):
    id = models.AutoField(primary_key=True, db_column="Address_id") # primary key and not null
    user_id = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    line = models.CharField( max_length=150, null=False) # not null
    city = models.CharField( max_length=50, validators =[validate_name])
    state = models.CharField(max_length=30)
    pincode = models.IntegerField(validators=[ MinValueValidator(0)])  # raise error if less than 0
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(blank=True,null=True) 
    


    def __str__(self):
        return f"{self.line}--{self.city}"


   


