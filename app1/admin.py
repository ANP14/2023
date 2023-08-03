from django.contrib import admin
from.models import Role, User,Address
# Register your models here.


#list display of Role
@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display=['id', 'role_name','code']



#list display of User
@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display=['id', 'first_name', 'last_name', 'role_id', 'email_id', 'password',]


#list display of Address
@admin.register(Address)
class AddressAdmin(admin.ModelAdmin):
    list_display=['id', 'line', 'city', 'state', 'pincode','user_id' ]