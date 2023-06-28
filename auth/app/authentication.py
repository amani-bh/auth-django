import jwt,datetime
from rest_framework import exceptions

def create_access_token(id):
    try:
        return jwt.encode({
            'user_id': id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
            'iat': datetime.datetime.utcnow()
        }, 'access_secret', algorithm='HS256')
    except jwt.PyJWTError:
        raise exceptions.AuthenticationFailed('Failed to create access token')

def decode_access_token(token):
    try:
        payload = jwt.decode(token, 'access_secret', algorithms='HS256')
        return payload['user_id']
    except jwt.PyJWTError:
        raise exceptions.AuthenticationFailed('Failed to decode access token')

def create_refresh_token(id):
    try:
        return jwt.encode({
            'user_id': id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7),
            'iat': datetime.datetime.utcnow()
        }, 'refresh_secret', algorithm='HS256')
    except jwt.PyJWTError:
        raise exceptions.AuthenticationFailed('Failed to create refresh token')

def decode_refresh_token(token):
    try:
        payload = jwt.decode(token, 'refresh_secret', algorithms='HS256')
        return payload['user_id']
    except jwt.PyJWTError:
        raise exceptions.AuthenticationFailed('Failed to decode refresh token')
