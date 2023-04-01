from django.urls import path
from .views import RegisterAPIView, LoginAPIView, UserAPIView, RefreshAPIView, LogoutAPIView, GoogleLoginView, \
    ActivationView

urlpatterns = [
    path('register', RegisterAPIView.as_view()),
    path('login', LoginAPIView.as_view()),
    path('user', UserAPIView.as_view()),
    path('refresh', RefreshAPIView.as_view()),
    path('logout', LogoutAPIView.as_view()),
    path('googleRegister', GoogleLoginView.as_view(), name='google_login_view'),
    path('activate/<uidb64>/<token>/', ActivationView.as_view(), name='activate'),
]
