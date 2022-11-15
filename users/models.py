# python imports
import os
import uuid
import random
# django imports
from django.db import models
from django.contrib.auth.models import (
    AbstractBaseUser, BaseUserManager, PermissionsMixin)
from django.core import validators
# django rest framework imports
from rest_framework_simplejwt.tokens import RefreshToken
# django phone number package imports
from phonenumber_field.modelfields import PhoneNumberField
# helper manually created fuctions imports from helpers file.
from .helpers import (alphaCharacterValidations, sepcialCharsValidation,
                    fileSize, allowedExtensipons, extessionErrorMessage)


class UserManger(BaseUserManager):
    def create_user(self, email, gender, fullname, username, dob, mobile, nationalNumber,country ,image, password=None):
        if email is None or email == "":
            raise TypeError("email must be provided")
        if gender is None or gender == "":
            raise TypeError("gender must be provided")
        if fullname is None or fullname == "":
            raise TypeError("fullname must be provided")
        if username is None or username == "":
            raise TypeError("second name must be provided")
        if dob is None or dob == "":
            raise TypeError("birth date  must be provided")
        if mobile is None or mobile == "":
            raise TypeError("mobile must be provided")
        if nationalNumber is None or nationalNumber == "":
            raise TypeError("country code must be provided")
        if country is None or country == "":
            raise TypeError("country must be provided")

        user = self.model(
            id=uuid.uuid1(),
            email=self.normalize_email(email), 
            gender=gender,
            fullname=fullname, 
            username=username,
            dob=dob,
            mobile=mobile,
            nationalNumber=nationalNumber,
            country=country,
            image=image
            )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, gender, fullname, username, dob, mobile, nationalNumber, country, password=None):
        if password is None:
            raise TypeError("password must be provided")
        user = self.create_user(email, gender, fullname, username, dob, mobile, nationalNumber, country, "", password)
        user.is_superuser = True
        user.is_staff = True
        user.isEmailVerified = True
        user.status = "2"
        user.isPhoneVerified = True
        user.status = True
        user.save(using=self._db)
        return user


class User(AbstractBaseUser, PermissionsMixin):
    genderChoices = [("Male", "Male"), ("Female", "Female"),("Other","Other")]
    
    id = models.UUIDField(primary_key=True, db_index=True)
    
    email = models.EmailField(
        max_length=255, unique=True, db_index=True, blank=False, null=False)

    gender = models.CharField(max_length=255, blank=False, null=False,
                            choices=genderChoices, validators=[alphaCharacterValidations])

    fullname = models.CharField(
        max_length=255, blank=False, null=False, validators=[alphaCharacterValidations])

    username = models.CharField(max_length=255, unique=True,validators=[
                                alphaCharacterValidations], blank=False, null=False)
    
    dob = models.DateField(blank=False, null=False)
    
    mobile = models.CharField(max_length=50,blank=False,null=False,unique=True, db_index=True)
    
    nationalNumber=PhoneNumberField(unique=True, db_index=True)

    country = models.CharField(max_length=255, blank=False, null=False)
    
    image=models.CharField(max_length=255,blank=True,null=True,default="")

    isEmailVerified = models.BooleanField(default=False)
    
    status = models.CharField(max_length=255, blank=True, null=True, default="2")
    
    isPhoneVerified = models.BooleanField(default=False)

    is_active = models.BooleanField(default=True)

    is_staff = models.BooleanField(default=False)

    createdAt = models.DateTimeField(auto_now_add=True)

    updatedAt = models.DateTimeField(auto_now=True)
    
    verificationcode = models.IntegerField(default=random.randint(100000, 999999))

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ["gender", "fullname", "username", "dob", "mobile", "nationalNumber", "country"]

    objects = UserManger()

    def __str__(self):
        return self.email

    def tokens(self):
        token = RefreshToken.for_user(self)
        return {
            'refresh': str(token),
            'access': str(token.access_token)
        }

class UserProfileImage(models.Model):
    image = models.FileField(upload_to="profile",validators=[fileSize, validators.FileExtensionValidator(allowedExtensipons,extessionErrorMessage)])

class TempMobileVirefication(models.Model):
    mobile=models.CharField(max_length=50)
    code=models.IntegerField()
    mobilestatus=models.BooleanField(default=False)