import json
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny
from rest_framework.response import Response
from rest_framework import  status
from rest_framework_simplejwt.tokens import RefreshToken
# from django.conf import settings
import re
from .customAuthentication import authenticate
from django.conf import settings
from django.http import HttpResponseRedirect
from django.db.models import Q
from django.utils import timezone
import jwt
import random
import uuid
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, smart_bytes
from .utils import (sendVerifyEmail,resetPasswordEmail,sentSMSVerificationCode,sentSMSResetPasswordCode)
from .models import(User,UserProfileImage,TempMobileVirefication)
from .serializers import (LoginWithPhoneSerializer,LoginWithEmailSerializer,
UserProfileImageSerializer,RegisterSerializer,resendEmailSerializer,CheckEmailIfExistSerializer,PasswordRestByPhone
,PasswordRestByEmail,CheckPhoneISerializer,ResetPassword,usenameSerializer,signupEmailSerializer,
signupPhoneSerializer,LoginWithUserNameSerializer)
from .permissions import IsVerified
from .language.authentication.signUp.singUpStep1 import (userexsisterror,
    authenticationError, mobileVireficationerror,validmobilenumberError,sendcodesuccessMessage,
    verificationSuccessMessage,notvalidCodeError,mobileExsistanceError,
    noUserExsisterrorMessage,notvalidphoneOrEmailOrUser,sendEmailsuccessfulyMessage,servererrorMessage,
    passwordValidationError,changePasswordSuccessfullyMessage)
frontEndDomain="http://170.187.154.46:8030/"
def check_email(email):
    regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    if(re.fullmatch(regex, email)):
        return email

    else:
        return None
def check_phone(phone):
    regex=r'^01[0-2]\d{1,8}$'
    if(re.fullmatch(regex, phone)):
        return phone

    else:
        return None

# login
@api_view(["POST"])
def login(request):
    if request.method =="POST":
        data = request.data 
        if not data :
            return Response({"error":"data must be provided"},status=status.HTTP_400_BAD_REQUEST)
        elif  not isinstance(data,dict):
            return Response({"error":"data must be object"},status=status.HTTP_400_BAD_REQUEST)
        elif "phoneOrEmailOrUsername" not in data.keys():
            return Response({"error":"'phoneOrEmailOrUsername' Field must be provided"},status=status.HTTP_400_BAD_REQUEST)
        elif "password" not in data.keys():
            return Response({"error":"'password' Field must be provided"},status=status.HTTP_400_BAD_REQUEST)
        if 'lang' in data.keys():
            pass
        elif 'lang' == "":
                data['lang']="en"
        else:
            data.update({'lang':"en"})
        serializer = ""
        if(re.search(".+@.+\..+",data["phoneOrEmailOrUsername"])):
            serializer = LoginWithEmailSerializer(data=data)
            if serializer.is_valid():
                pass
            else:
                return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
        elif check_phone(data["phoneOrEmailOrUsername"]):
            serializer = LoginWithPhoneSerializer(data=data)
            if serializer.is_valid():
                pass
            else:
                return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
        else:
            serializer = LoginWithUserNameSerializer(data=data)
            if serializer.is_valid():
                pass
            else:
                return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
        user = authenticate(phoneOrEmailOrUsername=data["phoneOrEmailOrUsername"],password=data["password"],status="1")
        
        if  user :
            if not user.isEmailVerified or not user.isPhoneVerified :
                return Response({
                    "user":{
                        "email":user.email,
                        "mobile":user.mobile,
                        "nationalNumber":user.nationalNumber.as_e164 ,
                        "email_verified":user.isEmailVerified,
                        "phone_verified":user.isPhoneVerified,
                    }
                }, status=status.HTTP_200_OK)
            return Response({"tokens":user.tokens(),"image":user.image}, status=status.HTTP_200_OK)
        else:
            return authenticationError( data['lang'])
            
# register
@api_view(["POST"])
def register(request):
    if request.method =="POST":
        try :
            data = request.data["data"]
        except KeyError : 
            return Response({"error":"data object must be provided"},status=status.HTTP_400_BAD_REQUEST)
        data = {}
        try:
            data = json.loads(request.data["data"])
        except :
            return Response({"not_valid_json_format":"json Format not valid "},status=status.HTTP_400_BAD_REQUEST)
        if not data :
            return Response({"error":"data must be provided"},status=status.HTTP_400_BAD_REQUEST)
        elif  not isinstance(data,dict):
            return Response({"error":"data must be object"},status=status.HTTP_400_BAD_REQUEST)
        dataKeys = data.keys()
        if "email" not in dataKeys:
            return Response({"error":"'email' field must be provided"})
        elif "gender" not in dataKeys:
            return Response({"error":"'gender' field must be provided"})
        elif "fullname" not in dataKeys:
            return Response({"error":"'fullName' field must be provided"})
        elif "dob" not in dataKeys:
            return Response({"error":"'birthDate' field must be provided"})
        elif "mobile" not in dataKeys:
            return Response({"error":"'mobile' field must be provided"})
        elif "nationalNumber" not in dataKeys:
            return Response({"error":"'nationalNumber' field must be provided"})
        elif "country" not in dataKeys:
            return Response({"error":"'country' field must be provided"})
        if 'lang' in dataKeys:
            pass
        elif 'lang' == "":
                data['lang']="en"
        else:
            data.update({'lang':"en"})
        
        serializer = RegisterSerializer(data=data)
        if serializer.is_valid():
            # try :
            image= request.FILES.get("image")
            imageName=""
            if  image :
                ImageSerilaizer = UserProfileImageSerializer(data={"image":image})
                if ImageSerilaizer.is_valid():
                    validIamge = UserProfileImage.objects.create(image=image)
                    imageName = validIamge.image.name
            now = timezone.now()
            id = uuid.uuid1()
            serializer.validated_data["id"] = id
            serializer.validated_data["verificationcode"] = random.randint(100000, 999999)
            serializer.validated_data["updatedAt"] = now
            serializer.validated_data["createdAt"] = now
            serializer.validated_data["dob"]=data["dob"]
            serializer.validated_data["is_active"] = True 
            serializer.validated_data["is_staff"] = False 
            serializer.validated_data["is_superuser"] = False
            serializer.validated_data["last_login"] = None
            serializer.validated_data["image"] = imageName
            serializer.validated_data["isEmailVerified"] = False
            serializer.validated_data["status"] = "2"
            serializer.validated_data["isPhoneVerified"] = False

            # temdata=TempMobileVirefication.objects.get(Q(mobile=data["mobile"]))
            # print()
            # print()
            # print()
            # print(temdata.mobile)
            # print(temdata.code)
            # print(temdata.mobilestatus)
            # print()
            # print()
            try:
                mobileData= TempMobileVirefication.objects.get(Q(mobile=data["mobile"]))
                if mobileData.mobilestatus == True:
                    user = User.objects.create(
                        **serializer.validated_data
                    )
                    user = User.objects.get(id=id)
                    user.set_password(serializer.validated_data["password"])
                    user.isPhoneVerified=True
                    user.status="1"
                    user.save()
                    mobileData.delete()
                print()
                print()
                print()
                print(user.isPhoneVerified)
                print()
                print()
                print()
            except:
                
                return mobileVireficationerror(data['lang'])

            sendVerifyEmail(request,user)
            return Response({
                "email":user.email,
                "mobile":user.mobile,
                "nationalNumber":data["nationalNumber"]
                },status=status.HTTP_201_CREATED)
            # except:
            #     return Response({"server_error":"something wrong in server , try later"},status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

@api_view(["POST"])
def checkEmailIfExist(request):
    data = request.data 
    if not data :
        return Response({"error":"data must be provided"},status=status.HTTP_400_BAD_REQUEST)
    elif  not isinstance(data,dict):
        return Response({"error":"data must be object"},status=status.HTTP_400_BAD_REQUEST)
    elif  "email" not in data.keys():
        return Response({"error":"'email' field must be provided"},status=status.HTTP_400_BAD_REQUEST)
    serializer = CheckEmailIfExistSerializer(data=data)
    if serializer.is_valid():
        try: 
            user = User.objects.get(email=serializer.validated_data["email"])
            if user : 
                return Response({"isEmailExist":True},status=status.HTTP_200_OK)
            else :
                return Response({"isEmailExist":False},status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"isEmailExist":False},status=status.HTTP_200_OK)
    else:
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

@api_view(["POST"])
def checkPhoneIfExist(request):
    data = request.data 
    if not data :
        return Response({"error":"data must be provided"},status=status.HTTP_400_BAD_REQUEST)
    elif  not isinstance(data,dict):
        return Response({"error":"data must be object"},status=status.HTTP_400_BAD_REQUEST)
    elif  "mobile" not in data.keys():
        return Response({"error":"'mobile' field must be provided"},status=status.HTTP_400_BAD_REQUEST)
    elif  "nationalNumber" not in data.keys():
        return Response({"error":"'nationalNumber' field must be provided"},status=status.HTTP_400_BAD_REQUEST)
    serializer = CheckPhoneISerializer(data=data)
    if serializer.is_valid():
        try : 
            user = User.objects.get(Q(mobile=data["mobile"])|Q(nationalNumber=data["nationalNumber"]))
            if user:
                return Response({"isPhoneExist":True,"isPhoneValid":True},status=status.HTTP_200_OK)
            else : 
                    return Response({"isPhoneExist":False,"isPhoneValid":True},status=status.HTTP_200_OK)
        except User.DoesNotExist : 
            return Response({"isPhoneExist":False,"isPhoneValid":True},status=status.HTTP_200_OK)
        except :
            return Response({"server_error":"something wrong in server , try later"},status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    else:
        return Response({
            "isPhoneValid":False,
            "isPhoneExist":False
            },status=status.HTTP_200_OK)

@api_view(["POST"])
def resendEmailVerfication(request):
    if request.method=="POST":
        data = request.data 
        if not data :
            return Response({"error":"data must be provided"},status=status.HTTP_400_BAD_REQUEST)
        elif  not isinstance(data,dict):
            return Response({"error":"data must be object"},status=status.HTTP_400_BAD_REQUEST)
        elif "email" not in data.keys():
            return Response({"error":"'email' field must be provided"})
        if 'lang' in data.keys():
            pass
        elif 'lang' == "":
                data['lang']="en"
        else:
            data.update({'lang':"en"})
        serializer = resendEmailSerializer(data=data)
        if serializer.is_valid():
            try :
                user = User.objects.get(email=serializer.validated_data["email"])
                try :
                    sendVerifyEmail(request,user)
                    return Response({"success":"email Resent Successfully"},status=status.HTTP_200_OK)
                except:
                    return Response({"email_error":"can't send email, try again"},status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            except User.DoesNotExist :
                return  Response({"not_exist":"no user exists with this email"},status=status.HTTP_404_NOT_FOUND)
        else:
                return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

@api_view(["GET"])
def verifyEmail(request):
    #will changed by the url of forntent domain
    
    token = request.GET.get("token", "")
    try:
        payload = jwt.decode(token, key=settings.SECRET_KEY, algorithms="HS256")
        user = User.objects.get(id=payload["user_id"])
        if not user.isEmailVerified:
            user.isEmailVerified = True
            user.status = "1"
            user.save()
        return HttpResponseRedirect(f"{frontEndDomain}register/phone-verify")
    except jwt.ExpiredSignatureError:
        return HttpResponseRedirect(f"{frontEndDomain}register/email-verify")
    except jwt.DecodeError:
        return HttpResponseRedirect(f"{frontEndDomain}errors/404")
    except:
        return HttpResponseRedirect(f"{frontEndDomain}errors/500")

def generateVerificationCode(data):
    verificationcode= random.randint(100000, 999999)
    print()
    print()
    print()
    print(verificationcode)
    print()
    print()
    if check_phone(data):
                    
        tempMobileData = TempMobileVirefication.objects.create(mobile=data,code=verificationcode)
        
        tempMobileData.save()
        tabledata=TempMobileVirefication.objects.filter(mobile=data).values()
        print()
        print()
        print()
        print(tabledata)
        print()
        print()
        print()
        print()
        mobiledata='+2'+str(tempMobileData.mobile)

        sentSMSVerificationCode(mobiledata,tempMobileData.code)
        return sendcodesuccessMessage(data['lang'])
    else:
        return validmobilenumberError(data['lang'])
@api_view(["POST"])
def SendverifyPhoneCode(request):
    if request.method =="POST":
        data = request.data 
        if not data :
            return Response({"error":"data must be provided"},status=status.HTTP_400_BAD_REQUEST)
        elif  not isinstance(data,dict):
            return Response({"error":"data must be object"},status=status.HTTP_400_BAD_REQUEST)
        elif  "mobile" not in data.keys():
            return Response({"error":"'mobile' field must be provided"},status=status.HTTP_400_BAD_REQUEST)
        # try :
        if 'lang' in data.keys():
            pass
        elif 'lang' == "":
                data['lang']="en"
        else:
            data.update({'lang':"en"})
        try:
            tempMobileData = TempMobileVirefication.objects.filter(mobile=data["mobile"]).values()
            # tempMobileData = TempMobileVirefication.objects.all().values()
            print()
            print()
            print()
            print(tempMobileData)
            print()
            print()
            if tempMobileData:
                
                tempMobileData = TempMobileVirefication.objects.get(Q(mobile=data["mobile"]))
                tempMobileData.delete()
                generateVerificationCode(data["mobile"])
                

            else:
                generateVerificationCode(data["mobile"])

        # except User.DoesNotExist:
        except :
            return Response({"error":"twillo mobile phone is not virified , try later"},status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
@api_view(["POST"])
def verifyPhone(request) :
    if request.method =="POST":
        data = request.data 
    if not data :
        return Response({"error":"data must be provided"},status=status.HTTP_400_BAD_REQUEST)
    elif  not isinstance(data,dict):
        return Response({"error":"data must be object"},status=status.HTTP_400_BAD_REQUEST) 
    elif  "code" not in data.keys ():
            return Response({"error":"'code' field must be provided"},status=status.HTTP_400_BAD_REQUEST)
    elif  "mobile" not in data.keys():
            return Response({"error":"'mobile' field must be provided"},status=status.HTTP_400_BAD_REQUEST)
    if 'lang' in data.keys():
            pass
    elif 'lang' == "":
            data['lang']="en"
    else:
        data.update({'lang':"en"})
    try :
        if check_phone(data['mobile']):
            # user = User.objects.get(Q(mobile=data["mobile"])|Q(nationalNumber=data["mobile"]))
            # mobileData=TempMobileVirefication.objects.all().values()
            mobileData= TempMobileVirefication.objects.filter(mobile=data["mobile"]).values()
            print()
            print()
            print(mobileData)
            print()
            print()
            print()
            
            if mobileData:
                codeCheck=TempMobileVirefication.objects.filter(code=int(data['code']))
                if codeCheck:
                    codeCheck.update(mobilestatus=True)
                    print()
                    print()
                    print(mobileData)
                    print()
                    print()
                    print()
                    return verificationSuccessMessage(data['lang'])
                else:
                    
                    return notvalidCodeError(data['lang'])
                
            else:
                return mobileExsistanceError(data['lang'])
    except :
        return Response({"server_error":"something error , try later"},status=status.HTTP_500_INTERNAL_SERVER_ERROR)
def findUserData(data):
    try:
    
        user = User.objects.get(Q(email=data["phoneOrEmailOrUsername"]) | Q(mobile=data["phoneOrEmailOrUsername"])|Q(username=data["phoneOrEmailOrUsername"]))
    
        if user:
            return Response({
                "user":{
                "username":user.username,
                "fullName":user.fullname,
                "email":user.email,
                "image":user.image,
                "mobile":user.mobile,
                "id":user.id
                }
                },status.HTTP_200_OK)
        else :
            return noUserExsisterrorMessage(data['lang'])
    except User.DoesNotExist:
        return noUserExsisterrorMessage(data['lang'])
    except :
        return servererrorMessage(data['lang'])
    
@api_view(["POST"])
def findUser(request):
    if request.method =="POST":
        data = request.data 
        if not data :
            return Response({"error":"data must be provided"},status=status.HTTP_400_BAD_REQUEST)
        elif  not isinstance(data,dict):
            return Response({"error":"data must be object"},status=status.HTTP_400_BAD_REQUEST)
        elif "phoneOrEmailOrUsername" not in data.keys():
            return Response({"error":"'phoneOrEmailOrUsername' Field must be provided"},status=status.HTTP_400_BAD_REQUEST)
        if 'lang' in data.keys():
            pass
        elif 'lang' == "":
            data['lang']="en"
        else:
            data.update({'lang':"en"})
            
        if check_email(data["phoneOrEmailOrUsername"]):
           return findUserData(data)
        elif check_phone(data["phoneOrEmailOrUsername"]):
           return  findUserData(data)
        else:
           if len(data["phoneOrEmailOrUsername"]) <=255 and data["phoneOrEmailOrUsername"] != "":
               return findUserData(data)
           else:
                return notvalidphoneOrEmailOrUser(data['lang'])

@api_view(["POST"])
def passwordRestVerificationByEmailOrMobile(request):
    if request.method =="POST":
        data = request.data 
        if not data :
            return Response({"error":"data must be provided"},status=status.HTTP_400_BAD_REQUEST)
        elif  not isinstance(data,dict):
            return Response({"error":"data must be object"},status=status.HTTP_400_BAD_REQUEST)
        elif "code" not in data.keys():
            return Response({"error":"'code' Field must be provided"},status=status.HTTP_400_BAD_REQUEST)
        elif "type" not in data.keys():
            return Response({"error":"'type' Field must be provided"},status=status.HTTP_400_BAD_REQUEST)
        elif data['type'] not in ['email','mobile']:
                return Response({"error":"'type' Field note valid"},status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(id=data['code'])
            if user:
                if data['type'] =='email':
                    resetPasswordEmail(user)
                    return sendEmailsuccessfulyMessage(data['lang'])
                elif data['type'] =='mobile':
                    passwordresetCode=random.randint(100000, 999999)
                    print()
                    print(passwordresetCode)
                    print()
                    print(user.mobile)
                    print()
                    print()
                    print()
                    sentSMSResetPasswordCode(user.mobile,passwordresetCode)
                    return sendcodesuccessMessage(data['lang'])
            else :
                return noUserExsisterrorMessage(data['lang'])
                    
        except User.DoesNotExist:
            return noUserExsisterrorMessage(data['lang'])
        
        except :
            return servererrorMessage(data['lang'])

@api_view(["POST"])
def passwordRestVerificationByEmail(request):
    if request.method =="POST":
        data = request.data 
        if not data :
            return Response({"error":"data must be provided"},status=status.HTTP_400_BAD_REQUEST)
        elif  not isinstance(data,dict):
            return Response({"error":"data must be object"},status=status.HTTP_400_BAD_REQUEST)
        elif "phoneOrEmail" not in data.keys():
            return Response({"error":"'phoneOrNumber' Field must be provided"},status=status.HTTP_400_BAD_REQUEST)
        serializer = ""
        if(re.search(".+@.+\..+",data["phoneOrEmail"])):
            serializer = PasswordRestByEmail(data=data)
            if serializer.is_valid():
                try:
                    user = User.objects.get(email=serializer.validated_data["phoneOrEmail"])
                    if user:
                        resetPasswordEmail(user)
                        return sendEmailsuccessfulyMessage(data['lang'])
                    else :
                        return  noUserExsisterrorMessage(data['lang'])
                
                except User.DoesNotExist:
                    return noUserExsisterrorMessage(data['lang'])
                
                except :
                    return servererrorMessage(data["lang"])
            else:
                return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
        else:
            serializer = PasswordRestByPhone(data=data)
            if serializer.is_valid():
                try:
                    user = User.objects.get(Q(mobile=data["mobile"])|Q(nationalNumber=data["mobile"]))
                    if user:
                        resetPasswordEmail(user)
                        return sendEmailsuccessfulyMessage(data['lang'])
                    else :
                        return  noUserExsisterrorMessage(data['lang'])
                
                except User.DoesNotExist:
                    return  noUserExsisterrorMessage(data['lang'])
                
                except :
                    return servererrorMessage(data['lang'])
            else:
                return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

@api_view(["POST"])
def passwordResetByTokens(request):
    if request.method =="POST":
        data = request.data 
        if not data :
            return Response({"error":"data must be provided"},status=status.HTTP_400_BAD_REQUEST)
        elif  not isinstance(data,dict):
            return Response({"error":"data must be object"},status=status.HTTP_400_BAD_REQUEST)
        elif "password" not in data.keys():
            return Response({"error":"'password' Field must be provided"},status=status.HTTP_400_BAD_REQUEST)
        elif "uuid" not in data.keys():
            return Response({"error":"'uuid' Field must be provided"},status=status.HTTP_400_BAD_REQUEST)
        elif "token" not in data.keys():
            return Response({"error":"'token' Field must be provided"},status=status.HTTP_400_BAD_REQUEST)
        serializer = ResetPassword(data=data)
        if serializer.is_valid():
            token = data["token"]
            try:
                # uuid = urlsafe_base64_decode(data["uuid"]).decode("UTF-8")
                uuid = smart_str(urlsafe_base64_decode(data["uuid"]))
                # payload = jwt.decode(token, key=settings.SECRET_KEY, algorithms="HS256")
                user = User.objects.get(id=uuid)
                if PasswordResetTokenGenerator().check_token(user, token):
                    user.set_password(serializer.validated_data["password"])
                    user.save()
                    return Response({"success":"password has reset successfully"},status=status.HTTP_200_OK)
                else:
                    return Response({"no_authorized":"user is not authorized to reset password"},status=status.HTTP_401_UNAUTHORIZED)
            except jwt.ExpiredSignatureError:
                return Response({"token_expired":"the token has been expired"},status=status.HTTP_400_BAD_REQUEST)
            except jwt.DecodeError:
                return Response({"not_valid_token":"the token is not valid"},status=status.HTTP_404_NOT_FOUND)
            except User.DoesNotExist:
                return Response({"user_not_exist":"user is not exist"},status=status.HTTP_404_NOT_FOUND)
            # except:
            #     return Response({"server_error":"there are something wrong"},status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
        else:
            return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

@api_view(["POST"])
def passwordRestVerificationByPhone(request):
    if request.method =="POST":
        data = request.data 
        if not data :
            return Response({"error":"data must be provided"},status=status.HTTP_400_BAD_REQUEST)
        elif  not isinstance(data,dict):
            return Response({"error":"data must be object"},status=status.HTTP_400_BAD_REQUEST)
        elif "phoneOrEmail" not in data.keys():
            return Response({"error":"'phoneOrNumber' Field must be provided"},status=status.HTTP_400_BAD_REQUEST)
        serializer = ""
        if(re.search(".+@.+\..+",data["phoneOrEmail"])):
            serializer = PasswordRestByEmail(data=data)
            if serializer.is_valid():
                try:
                    user = User.objects.get(email=serializer.validated_data["phoneOrEmail"])
                    if user:
                        user.verificationcode= random.randint(100000, 999999) 
                        user.save()
                        token = str(RefreshToken.for_user(user).access_token)
                        sentSMSResetPasswordCode(str(user.nationalNumber),user.verificationcode)
                        return Response({"restPasswordCodeToken":token},status=status.HTTP_200_OK)
                    else :
                        return Response({"not_Exist":"no user exists with this email "},status=status.HTTP_404_NOT_FOUND)
                
                except User.DoesNotExist:
                    return Response({"not_Exist":"no user exists with this email "},status=status.HTTP_404_NOT_FOUND)
                
                except :
                    return Response({"error":"can't send email try later"},status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            else:
                return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
        else:
            serializer = PasswordRestByPhone(data=data)
            if serializer.is_valid():
                try:
                    user = User.objects.get(Q(mobile=data["mobile"])|Q(nationalNumber=data["mobile"]))
                    if user:
                        user.verificationcode= random.randint(100000, 999999) 
                        user.save()
                        token = str(RefreshToken.for_user(user).access_token)
                        sentSMSResetPasswordCode(str(user.nationalNumber),user.verificationcode)
                        return Response({"restPasswordCodeToken":token},status=status.HTTP_200_OK)
                    else :
                        return Response({"not_Exist":"no user exists with this phone number "},status=status.HTTP_404_NOT_FOUND)
                
                except User.DoesNotExist:
                    return Response({"not_Exist":"no user exists with this phone number  "},status=status.HTTP_404_NOT_FOUND)
                
                except :
                    return Response({"error":"can't send email try later"},status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            else:
                return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

@api_view(["POST"])
def passwordResetByPhoneCodeCheck(request):
    if request.method =="POST":
        data = request.data 
        if not data :
            return Response({"error":"data must be provided"},status=status.HTTP_400_BAD_REQUEST)
        elif  not isinstance(data,dict):
            return Response({"error":"data must be object"},status=status.HTTP_400_BAD_REQUEST)
        elif "code" not in data.keys():
            return Response({"error":"'code' Field must be provided"},status=status.HTTP_400_BAD_REQUEST)
        elif "restPasswordCodeToken" not in data.keys():
            return Response({"error":"'restPasswordCodeToken' Field must be provided"},status=status.HTTP_400_BAD_REQUEST)
        try :
            token = data["restPasswordCodeToken"]
            payload = jwt.decode(token, key=settings.SECRET_KEY, algorithms="HS256")
            userId = payload["user_id"]
            user = User.objects.get(id=userId)
            if user.verificationcode == int(data["code"]):
                token = str(RefreshToken.for_user(user).access_token)
                return Response({"validCodeToken":token},status=status.HTTP_200_OK)
            else :
                return Response({"not_valid_code":"code Is not valid"},status=status.HTTP_400_BAD_REQUEST)
        except jwt.ExpiredSignatureError:
            return Response({"token_expired":"the token has been expired"},status=status.HTTP_400_BAD_REQUEST)
        except jwt.DecodeError:
            return Response({"not_valid_token":"the token is not valid"},status=status.HTTP_404_NOT_FOUND)
        except User.DoesNotExist:
            return Response({"user_not_exist":"user is not exist"},status=status.HTTP_404_NOT_FOUND)
        except:
            return Response({"server_error":"there are something wrong"},status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
        
@api_view(["POST"])
def passwordResetByPhone(request):
    if request.method =="POST":
        data = request.data 
        if not data :
            return Response({"error":"data must be provided"},status=status.HTTP_400_BAD_REQUEST)
        elif  not isinstance(data,dict):
            return Response({"error":"data must be object"},status=status.HTTP_400_BAD_REQUEST)
        elif "password" not in data.keys():
            return Response({"error":"'code' Field must be provided"},status=status.HTTP_400_BAD_REQUEST)
        elif "validCodeToken" not in data.keys():
            return Response({"error":"'validCodeToken' Field must be provided"},status=status.HTTP_400_BAD_REQUEST)
        serializer = ResetPassword(data=data)
        if serializer.is_valid():
            token = data["validCodeToken"]
            try:
                    payload = jwt.decode(token, key=settings.SECRET_KEY, algorithms="HS256")
                    user = User.objects.get(id=payload["user_id"])
                    user.set_password(serializer.validated_data["password"])
                    user.save()
                    return Response({"success":"password is reset successfully"},status=status.HTTP_200_OK)

            except jwt.ExpiredSignatureError:
                return Response({"token_expired":"the token has been expired"},status=status.HTTP_400_BAD_REQUEST)
            except jwt.DecodeError:
                return Response({"not_valid_token":"the token is not valid"},status=status.HTTP_404_NOT_FOUND)
            except User.DoesNotExist:
                return Response({"user_not_exist":"user is not exist"},status=status.HTTP_404_NOT_FOUND)
            except:
                return Response({"server_error":"there are something wrong"},status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                    
        else:
            return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

@api_view(["POST"])
def checkUserEmailVerified(request):
    if request.method=="POST":
        data = request.data 
        if not data :
            return Response({"error":"data must be provided"},status=status.HTTP_400_BAD_REQUEST)
        elif  not isinstance(data,dict):
            return Response({"error":"data must be object"},status=status.HTTP_400_BAD_REQUEST)
        elif "email" not in data.keys():
            return Response({"error":"'email' field must be provided"})
        serializer = resendEmailSerializer(data=data)
        if serializer.is_valid():
            try :
                user = User.objects.get(email=serializer.validated_data["email"])
                return Response({"email_verified":user.isEmailVerified},status=status.HTTP_200_OK)
            except User.DoesNotExist :
                return  Response({"not_exist":"no user exists with this email"},status=status.HTTP_404_NOT_FOUND)
            except :
                return  Response({"server_error":"something wrong , try again later"},status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

@api_view(["POST"])
def checkUserPhoneVerified(request):
    data = request.data 
    if not data :
        return Response({"error":"data must be provided"},status=status.HTTP_400_BAD_REQUEST)
    elif  not isinstance(data,dict):
        return Response({"error":"data must be object"},status=status.HTTP_400_BAD_REQUEST)
    elif  "mobile" not in data.keys():
        return Response({"error":"'mobile' field must be provided"},status=status.HTTP_400_BAD_REQUEST)
    try :
            user = User.objects.get(Q(mobile=data["mobile"])|Q(nationalNumber=data["mobile"]))
            if user:
                    return Response({"phone_verified":user.isPhoneVerified,"email_verified":user.isEmailVerified},status=status.HTTP_200_OK)
            else:
                return Response({"not_exist":"no user exists with this phone"},status=status.HTTP_404_NOT_FOUND)
    except User.DoesNotExist:
        return Response({"not_exist":"no user exists with this phone"},status=status.HTTP_404_NOT_FOUND)
    except :
        return Response({"server_error":"something error , try later"},status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
############## new code by hadeer #######
def saveData(data):
        signupField=data['signupField']
        inputype=data['type']
        password=data['password']
        lang=data['lang']
        statusbool=False
        user =User.objects.filter(Q(email=signupField) | Q(mobile=signupField) |Q(username=signupField))
        if user:
            statusbool=True
            error_message=userexsisterror(lang)
            error={'status':statusbool,'error_message':error_message}
            return Response(error,status=status.HTTP_400_BAD_REQUEST)
        else:
            statusbool=False
            error={'status':statusbool}
            return Response(error,status=status.HTTP_400_BAD_REQUEST)

@api_view(["POST"])
def singUpStep1(request):
    data = request.data 
    datakeys=list(data.keys())
    if not data :
        return Response({"error":"data must be provided"},status=status.HTTP_400_BAD_REQUEST)
    if 'signupField' in data.keys():
        pass
    else:
        return Response({"error":"'mobile' or 'usename' pr 'email' field must be provided"},status=status.HTTP_400_BAD_REQUEST)
    if 'lang' in data.keys():
        pass
    elif 'lang' == "":
        data['lang']="en"
    else:
        data.update({'lang':"en"})
        # return Response({"error":"lang field must be provided"},status=status.HTTP_400_BAD_REQUEST)
    if 'type' in data.keys():
        pass
    else:
        return Response({"error":"type field must be provided"},status=status.HTTP_400_BAD_REQUEST)
    if 'password' in data.keys():
        pass
    else:
        return Response({"error":"password field must be provided"},status=status.HTTP_400_BAD_REQUEST)

    if data['type'] in ['email','mobile','username']:
        type=data['type']
    else:
        return Response({"error":"type value must be 'mobile','email' , 'username'"},status=status.HTTP_400_BAD_REQUEST)
    checkFlag=0
    if check_email(data['signupField']):
        emailSerializer=signupEmailSerializer(data=request.data)
        if emailSerializer.is_valid():
            return saveData(data)
        else:
             return Response(emailSerializer.errors,status=status.HTTP_400_BAD_REQUEST)
   
    elif check_phone(data['signupField']):
        phoneSerializer=signupEmailSerializer(data=request.data)
        if phoneSerializer.is_valid():
            return saveData(data)
        else:
             return Response(phoneSerializer.errors,status=status.HTTP_400_BAD_REQUEST)
    else:
        serialzer =usenameSerializer(data=request.data)
        if serialzer.is_valid():
            return saveData(data)
        else:
            return Response(serialzer.errors,status=status.HTTP_400_BAD_REQUEST)

@api_view(["POST"])
def changePassword(request):
    data = request.data 
    datakeys=data.keys()
    if not data :
        return Response({"error":"data must be provided"},status=status.HTTP_400_BAD_REQUEST)
    if 'password' not in datakeys:
            return Response({"error":"'password' Field must be provided"},status=status.HTTP_400_BAD_REQUEST)
    elif 'userCode' not in datakeys:
            return Response({"error":"'userCode' Field must be provided"},status=status.HTTP_400_BAD_REQUEST)
    if 'lang' in data.keys():
        pass
    elif 'lang' == "":
        data['lang']="en"
    else:
        data.update({'lang':"en"})
    try:
        user = User.objects.get(id=data['userCode'])
        if user:
            passwordValid = user.check_password(data['password'])
            # check if valid, then return user
            if passwordValid:            
                return passwordValidationError(data['lang'])
            else:
                serializer=ResetPassword(data=data)
                if serializer.is_valid():
                    print()
                    print()
                    print()
                    print(user.password)
                    print()
                    print()
                    print()
                    user.set_password(data['password'])
                    user.save()
                    print()
                    print()
                    print()
                    print(user.password)
                    print()
                    print()
                    print()
                    return changePasswordSuccessfullyMessage(data['lang'])
                else:
                    return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
        else :
            return noUserExsisterrorMessage(data['lang'])
                
    except User.DoesNotExist:
        return noUserExsisterrorMessage(data['lang'])
    
    except :
        return servererrorMessage(data['lang'])
    

    


       
            
            

            
    
