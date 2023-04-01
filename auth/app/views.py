from google.auth.transport import requests
from google.oauth2 import id_token
from rest_framework import status
from rest_framework.authentication import get_authorization_header
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.exceptions import APIException, AuthenticationFailed

from .authentication import create_access_token, create_refresh_token, decode_access_token, decode_refresh_token
from .serializers import UserSerializer
from .models import User


class RegisterAPIView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


class LoginAPIView(APIView):
    def post(self, request):
        user = User.objects.filter(email=request.data['email']).first()

        if not user:
            raise APIException('Invalid credentials!')

        if not user.check_password(request.data['password']):
            raise APIException('Invalid credentials!')

        access_token = create_access_token(user.id)
        refresh_token = create_refresh_token(user.id)

        response = Response()

        response.set_cookie(key='refreshToken', value=refresh_token, httponly=True)
        response.data = {
            'token': access_token
        }

        return response


class UserAPIView(APIView):
    def get(self, request):
        auth = get_authorization_header(request).split()

        if auth and len(auth) == 2:
            token = auth[1].decode('utf-8')
            id = decode_access_token(token)

            user = User.objects.filter(pk=id).first()

            return Response(UserSerializer(user).data)

        raise AuthenticationFailed('unauthenticated')


class RefreshAPIView(APIView):
    def post(self, request):
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        access_token = create_access_token(id)
        return Response({
            'token': access_token
        })


class LogoutAPIView(APIView):
    def post(self, _):
        response = Response()
        response.delete_cookie(key="refreshToken")
        response.data = {
            'message': 'success'
        }
        return response


class GoogleLoginView(APIView):
    def post(self, request):
        id_token1 = request.data.get('id_token')
        if not id_token1:
            return Response(status=status.HTTP_400_BAD_REQUEST)

        try:
            # Specify the CLIENT_ID of the app that accesses the backend:
            idinfo = id_token.verify_oauth2_token(id_token1, requests.Request(), '767545735730-dbak9de0g63e2n8ou2vnuefgm0c74jvq.apps.googleusercontent.com')

            # Get user information from idinfo
            email = idinfo['email']
            first_name = idinfo.get('given_name', '')
            last_name = idinfo.get('family_name', '')

            # Check if user already exists
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                # Create new user
                 serializer = UserSerializer(data={
                        "email": email,
                        "first_name": first_name,
                        "last_name": last_name,
                        "phone":"21333",
                        "password":"123"
                    })
                 serializer.is_valid(raise_exception=True)
                 user=serializer.save()

            # Set is_active to True
            user.is_active = True
            user.save()
            # Generate JWT token and send in response
            access_token = create_access_token(user.id)
            refresh_token = create_refresh_token(user.id)
            response = Response()
            response.set_cookie(key='refreshToken', value=refresh_token, httponly=True)
            response.data = {'token': access_token}
            return response

        except ValueError:
        # Invalid token
           return Response(status=status.HTTP_400_BAD_REQUEST)
