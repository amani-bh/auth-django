from django.conf import settings
from google.auth.transport import requests
from google.oauth2 import id_token
from rest_framework import status
from rest_framework.authentication import get_authorization_header
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.exceptions import APIException, AuthenticationFailed

from .authentication import create_access_token, create_refresh_token, decode_access_token, decode_refresh_token
from .serializers import UserSerializer, NotificationSerializer
from .models import User, Notification
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.core.mail import send_mail
from django.urls import reverse

from .tokens import account_activation_token


user_not_found='user not found'


class RegisterAPIView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user=serializer.save()

        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        token = account_activation_token.make_token(user)
        join_url = f"http://localhost:3001/activate/{uidb64}/{token}"

        send_mail(
            'Activate your account',
            f'Hi {user.first_name} {user.last_name}, please activate your account by clicking on the link below: {join_url}',
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            fail_silently=False,
        )

        return Response(serializer.data)


class LoginAPIView(APIView):
    def post(self, request):
        user = User.objects.filter(email=request.data['email']).first()

        if not user:
            raise APIException('Invalid credentials!')
        if not user.is_active:
            raise APIException('Verify your mail !')

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
            user_id = decode_access_token(token)
            user = User.objects.filter(pk=user_id).first()
            return Response(UserSerializer(user).data)
        raise AuthenticationFailed('unauthenticated')


class RefreshAPIView(APIView):
    def post(self, request):
        refresh_token = request.COOKIES.get('refreshToken')
        user_id = decode_refresh_token(refresh_token)
        access_token = create_access_token(user_id)
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

            idinfo = id_token.verify_oauth2_token(id_token1, requests.Request(), '767545735730-dbak9de0g63e2n8ou2vnuefgm0c74jvq.apps.googleusercontent.com')

            email = idinfo['email']
            first_name = idinfo.get('given_name', '')
            last_name = idinfo.get('family_name', '')
            image_url=idinfo.get('picture', '')

            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                 serializer = UserSerializer(data={
                        "email": email,
                        "first_name": first_name,
                        "last_name": last_name,
                        "phone": "21333",
                        "password": "123",
                        "image_url": image_url
                    })
                 serializer.is_valid(raise_exception=True)
                 user = serializer.save()


            user.is_active = True
            user.save()

            access_token = create_access_token(user.id)
            refresh_token = create_refresh_token(user.id)
            response = Response()
            response.set_cookie(key='refreshToken', value=refresh_token, httponly=True)
            response.data = {'token': access_token}
            return response

        except ValueError:
           return Response(status=status.HTTP_400_BAD_REQUEST)


# activate account
class ActivationView(APIView):
    def get(self, request, uidb64, token):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(id=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user and account_activation_token.check_token(user, token):
            user.is_active = True
            user.save()
            return Response({'message': 'Activation successful!'}, status=status.HTTP_200_OK)

        return Response({'message': 'Activation link is invalid!'}, status=status.HTTP_400_BAD_REQUEST)


class ImageUploadView(APIView):
    def post(self, request):
        image_url = request.data.get('image_url')
        user_id = request.data.get('id')
        try:
            user = User.objects.filter(pk=user_id).first()
            user.image_url = image_url
            user.save()
            return Response(UserSerializer(user).data)
        except User.DoesNotExist:
            return Response({'error': user_not_found}, status=status.HTTP_400_BAD_REQUEST)


class UpdateProfile(APIView):
    def post(self, request):
        first_name = request.data.get('first_name')
        user_id = request.data.get('id')
        last_name = request.data.get('last_name')
        phone = request.data.get('phone')
        email = request.data.get('email')
        try:
            user = User.objects.filter(pk=user_id).first()
            serializer = UserSerializer(user, data={'first_name': first_name, 'last_name': last_name,
                                                    'phone': phone, 'email': email}, partial=True)
            serializer.is_valid(raise_exception=True)
            user = serializer.save()
            return Response(UserSerializer(user).data)
        except User.DoesNotExist:
            return Response({'error': user_not_found}, status=status.HTTP_400_BAD_REQUEST)


class UpdatePassword(APIView):
    def post(self, request):
        user_id = request.data.get('id')
        password = request.data.get('password')
        try:
            user = User.objects.filter(pk=user_id).first()
            serializer = UserSerializer(user, data={'password': password}, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.update_password(user, serializer.validated_data)
            return Response({'message': 'Password updated successfully!'}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'error': user_not_found}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
def get_user(request, id):
    try:
        user = User.objects.get(pk=id)
        return Response(UserSerializer(user).data)

    except User.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)


@api_view(['GET'])
def all_users(request):
    users = User.objects.filter(is_active=True)
    serializer = UserSerializer(users, many=True)
    return Response(serializer.data)


@api_view(['GET'])
def user_autocomplete(request):
    query = request.query_params.get('query', '')
    queryset = User.objects.filter(email__icontains=query)[:10]
    serializer = UserSerializer(queryset, many=True)
    return Response(serializer.data)


@api_view(['GET'])
def disable_user(request,id):
    user = User.objects.get(pk=id)
    user.is_active=False
    user.save()
    users = User.objects.filter(is_active=True)
    serializer = UserSerializer(users, many=True)
    return Response(serializer.data)


@api_view(['GET'])
def points_user(request, id):
    user = User.objects.get(pk=id)
    user.points += 5
    if user.points >= 100:
        user.badge='Responder'
    elif user.points >= 200:
        user.badge='Contributor'
    elif user.points >= 500:
        user.badge='Expert'

    user.save()

    serializer = UserSerializer(user)
    return Response(serializer.data)


@api_view(['POST'])
def add_notification(request, id):
    try:
        user = User.objects.get(pk=id)
        serializer=NotificationSerializer(data={
            'user':user.id,
            'message':request.data['message']
        })

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        else:
            return Response(serializer.errors ,status=status.HTTP_400_BAD_REQUEST)

    except User.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)


@api_view(['GET'])
def all_notification(request, id):
    user = User.objects.get(pk=id)
    notifications= Notification.objects.filter(user=user, seen=False).order_by('-created_at')
    if notifications:
        serializer=NotificationSerializer(notifications, many=True)
        return Response(serializer.data)
    else:
        return Response([])
    return Response(status=status.HTTP_404_NOT_FOUND)


@api_view(['POST'])
def seen_notification(request):
    notif_data=request.data['notifications']
    for notif in notif_data:
        update_notif=Notification.objects.get(pk=notif['id'])
        update_notif.seen=True
        update_notif.save()
    return Response(status=status.HTTP_200_OK)

