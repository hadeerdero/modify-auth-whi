from os import error
from typing import Tuple
from rest_framework import serializers
from .models import User, UserProfileImage
from django.db import models
from phonenumber_field.modelfields import PhoneNumberField
from django.core.exceptions import ValidationError
from django.core import validators


###########################start global image validation ###############################
allowedExtensipons = ['jpg', 'png', 'jpeg', 'gif']
extessionErrorMessage = "allowed format is :  'jpg', 'png', 'jpeg',  'gif' "
def fileSize(value):
    limit = 10 * 1024 * 1000
    if value.size > limit:
        raise ValidationError('File too large. Size should not exceed 10 MiB.')

class ImageValidation(models.Model):
    image = models.FileField(upload_to="test",
                            validators=[fileSize,validators.FileExtensionValidator(allowedExtensipons,extessionErrorMessage)])
    class Meta:
        managed = False
###########################end global image validation ###########################################
####################start authentication #########################################################
class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        min_length=8, max_length=68, required=True)
    class Meta:
        model = User
        fields =["email", "gender", "username", "fullname", "dob", "mobile","nationalNumber","country","password"]

class UserProfileImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfileImage
        fields="__all__"

class LoginWithEmailSerializer(serializers.Serializer):
    phoneOrEmailOrUsername = serializers.EmailField(max_length=255, required=True)
    password = serializers.CharField(max_length=68,required=True, write_only=True)

class LoginWithPhoneSerializer(serializers.Serializer):
    phoneOrEmailOrUsername = serializers.IntegerField(required=True)
    password = serializers.CharField(max_length=68,required=True, write_only=True)

class LoginWithUserNameSerializer(serializers.Serializer):
    phoneOrEmailOrUsername = serializers.CharField(max_length=255,min_length=2,required=True)
    password = serializers.CharField(max_length=68,required=True, write_only=True)
    
class resendEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

class CheckEmailIfExistSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

class checkPhoneNumberValidtions(models.Model):
    mobile = models.CharField(max_length=50)
    nationalNumber=PhoneNumberField()
    class Meta:
        managed = False


class CheckPhoneISerializer(serializers.ModelSerializer):
    class Meta:
        model = checkPhoneNumberValidtions
        fields="__all__"
        
    
class PasswordRestByPhone(serializers.Serializer):
    phoneOrEmail = serializers.IntegerField(required=True)

class PasswordRestByEmail(serializers.Serializer):
    phoneOrEmail = serializers.EmailField(max_length=255, required=True)

class ResetPassword(serializers.Serializer):
    password = serializers.CharField(min_length=8, max_length=68, required=True)
    
class usenameSerializer(serializers.Serializer):
    signupField=serializers.CharField(max_length=255, required=True)
    type=serializers.CharField(max_length=255, required=True)
    password=serializers.CharField(min_length=8, max_length=68, required=True)

class signupEmailSerializer(serializers.Serializer):
    signupField = serializers.EmailField(max_length=255, min_length=2,required=True)
    type=serializers.CharField(max_length=255, required=True)
    password=serializers.CharField(min_length=8, max_length=68, required=True)

class signupPhoneSerializer(serializers.Serializer):
    signupField = serializers.IntegerField(required=True)
    type=serializers.CharField(max_length=255, required=True)
    password=serializers.CharField(min_length=8, max_length=68, required=True)
####################end authentication #########################################################