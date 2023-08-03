from django.urls import path, include
from django.shortcuts import HttpResponse
# from employee import views
from .views import UsersCreate, RoleView, UploadFileView, LoginAPI, LogoutUser, Userview_cookies, LoginAPI_cookies, LogoutUser_cookies


urlpatterns = [
    path("users/", UsersCreate.as_view(), name = "users"),
    path("users/<int:id>/", UsersCreate.as_view(), name = "emp"),
    path("roles/", RoleView.as_view(), name = "roles"),
    path("roles/<int:id>/", RoleView.as_view(), name = "roleid"),
    path("upload/", UploadFileView.as_view(), name="upload-file"),
    path("download/", UploadFileView.as_view(), name="dload-file"),
    path("loginapi/", LoginAPI.as_view(), name = "login"),
    # path("view/", Userview.as_view(), name = "login"),
    path("logout/", LogoutUser.as_view(), name = "logout"),
    path("loginapi_cookies/", LoginAPI_cookies.as_view(), name = "login"),
    path("view_cookies/", Userview_cookies.as_view(), name = "login"),
    path("logout_cookies/", LogoutUser_cookies.as_view(), name = "logout"),

]
