from django.urls import path

from . import views
from .views import RegisterAPIView, LoginAPIView, UserAPIView, RefreshAPIView, LogoutAPIView, GoogleLoginView, \
    ActivationView, ImageUploadView, UpdateProfile, UpdatePassword

urlpatterns = [
    path('register', RegisterAPIView.as_view(), name='register'),
    path('login', LoginAPIView.as_view(), name='login'),
    path('user', UserAPIView.as_view(), name='user'),
    path('refresh', RefreshAPIView.as_view(), name='refresh'),
    path('logout', LogoutAPIView.as_view()),
    path('googleRegister', GoogleLoginView.as_view(), name='google_login_view'),
    path('activate/<uidb64>/<token>/', ActivationView.as_view(), name='activate'),
    path('uploadImage', ImageUploadView.as_view()),
    path('updateProfile', UpdateProfile.as_view()),
    path('updatePassword', UpdatePassword.as_view()),
    path('get_user/<int:id>/', views.get_user, name="get_user"),
    path('all_users/', views.all_users ),
    path('user_autocomplete/', views.user_autocomplete ),
    path('disable_user/<int:id>', views.disable_user ),
]
