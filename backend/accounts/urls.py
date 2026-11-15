from django.urls import path

from . import views
from .views import UserLoginView, UserLogoutView, register

app_name = "accounts"

urlpatterns = [
    path("register/", register, name="register"),
    path("login/", UserLoginView.as_view(), name="login"),
    path("logout/", UserLogoutView.as_view(), name="logout"),
    path("profile/", views.profile, name="profile"),
    path("manage/", views.user_management, name="user_management"),
    path("analysts/", views.user_management, name="analyst_management"),
]
