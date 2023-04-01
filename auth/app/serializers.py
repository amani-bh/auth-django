from rest_framework import serializers
from .models import User


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name', 'email','phone', 'password'] # fields needs to return in response
        extra_kwargs = {
            'password': {'write_only': True}, # password will not return in response only write
            'is_active': {'default': False}
        }

# use this function to hash the password when adding to database
    def create(self, validated_data):
        password = validated_data.pop('password', None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance
