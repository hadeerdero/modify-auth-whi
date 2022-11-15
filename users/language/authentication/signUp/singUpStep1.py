from rest_framework.response import Response
from rest_framework import  status
def userexsisterror(lang):
    if lang == 'en':
        return {"error":"Email Or Phone Or USername Already exsists"}
    elif lang == 'ar':        
        return {"خطاء":"الاميل او التليفون او اسم المستخدم موجودين بالفعل "}
    elif lang == "":
        return {"error":"Email Or Phone Or USername Already exsists"}
    else:
        return {"error":"not valid language "}    
def authenticationError(lang):
    if lang=='en': 
        return Response({"error":"email or phone or username or password is not valid"},status=status.HTTP_401_UNAUTHORIZED)
    elif lang == 'ar':      
        return Response({"error":" الاميل او اسم المستخدم او التليفون او كلمة المرور  غير صالحين "},status=status.HTTP_401_UNAUTHORIZED)
    elif lang == "":
        return Response({"not_authenticated":"email or phone or username or password is not valid"},status=status.HTTP_401_UNAUTHORIZED)
    else:
        return Response({"error","not valid language "},status=status.HTTP_400_BAD_REQUEST)
def mobileVireficationerror(lang):
    
   
    if lang=='en': 
        return Response({"error":"verify your phone number first"},status=status.HTTP_400_BAD_REQUEST)
    elif lang == 'ar':   
        return Response({"error":"الرجاء تأكيد رقم التليفون اولا"},status=status.HTTP_400_BAD_REQUEST)
   
    elif lang == "":
        return Response({"error":"verify your phone number first"},status=status.HTTP_400_BAD_REQUEST)
    else:
        return Response({"error","not valid language "},status=status.HTTP_400_BAD_REQUEST)
def validmobilenumberError(lang):
    if lang=='en': 
        return Response({"error":"not valid phone number"},status=status.HTTP_400_BAD_REQUEST)

    elif lang=='ar': 
        return Response({"error":"رقم التليفون الذي ادخلته غير صحيح"},status=status.HTTP_400_BAD_REQUEST)
    elif lang=="":
        return Response({"error":"not valid phone number"},status=status.HTTP_400_BAD_REQUEST)
    else:
        return Response({"error","not valid language "},status=status.HTTP_400_BAD_REQUEST)
def sendcodesuccessMessage(lang):
    if lang=='en': 
        return Response({"success":"code sent successfully"},status=status.HTTP_200_OK)
    elif lang=='ar': 
        return Response({"نجاح":"تم ارسال الكود بنجاح"},status=status.HTTP_200_OK)
    elif lang=="":
        return Response({"success":"code sent successfully"},status=status.HTTP_200_OK)
    else:
        return Response({"error","not valid language "},status=status.HTTP_400_BAD_REQUEST)    
def verificationSuccessMessage(lang):
    if lang=='en': 
        return Response({"success":"phone is Verified successfully"},status=status.HTTP_200_OK)

    elif lang=='ar': 
        return Response({"نجاح":"تم تاكيد رقم التليفون  بنجاح"},status=status.HTTP_200_OK)
    elif lang=="":
       return  Response({"success":"phone is Verified successfully"},status=status.HTTP_200_OK)
    else:
        return Response({"error","not valid language "},status=status.HTTP_400_BAD_REQUEST)
def notvalidCodeError(lang):
    if lang=='en': 
        return Response({"not_valid_code":"Not Valid Code"},status=status.HTTP_400_BAD_REQUEST)

    elif lang=='ar': 
        return Response({"error":"الكود غير صالح"},status=status.HTTP_400_BAD_REQUEST)
    elif lang=="":
       return  Response({"not_valid_code":"Not Valid Code"},status=status.HTTP_400_BAD_REQUEST)
    else:
        return Response({"error","not valid language "},status=status.HTTP_400_BAD_REQUEST)
def mobileExsistanceError(lang):
    
    if lang=='en': 
        return Response({"error":"no mobile exists with this number"},status=status.HTTP_404_NOT_FOUND)

    elif lang=='ar': 
        return Response({"error":"هذا الرقم غير موجود"},status=status.HTTP_404_NOT_FOUND)
    elif lang=="":
       return  Response({"error":"no mobile exists with this number"},status=status.HTTP_404_NOT_FOUND)
    else:
        return Response({"error","not valid language "},status=status.HTTP_400_BAD_REQUEST)
def noUserExsisterrorMessage(lang):
    if lang=='en': 
        return Response({"not_exist":"no user exists  "},status=status.HTTP_404_NOT_FOUND)

    elif lang=='ar': 
        return Response({"error":"هذا المستخدم غير موجود"},status=status.HTTP_404_NOT_FOUND)
    elif lang=="":
       return Response({"not_exist":"no user exists  "},status=status.HTTP_404_NOT_FOUND)
    else:
        return Response({"error","not valid language "},status=status.HTTP_400_BAD_REQUEST)
def notvalidphoneOrEmailOrUser(lang):
    if lang=='en': 
        return Response({"error":"'phoneOrEmailOrUsername' is not valid "},status=status.HTTP_400_BAD_REQUEST)

    elif lang=='ar': 
        return Response({"error":"التليفون او الاميل او اسم المستخدم غير صالح"},status=status.HTTP_400_BAD_REQUEST)
    elif lang=="":
       return Response({"error":"'phoneOrEmailOrUsername' is not valid "},status=status.HTTP_400_BAD_REQUEST)
    else:
        return Response({"error","not valid language "},status=status.HTTP_400_BAD_REQUEST)
def sendEmailsuccessfulyMessage(lang):
    if lang=='en': 
        return Response({"success":"email is sent successfully"},status=status.HTTP_200_OK)

    elif lang=='ar': 
        return Response({"نجاح":"تم ارسال الايميل بنجاح"},status=status.HTTP_200_OK)
    elif lang=="":
       return Response({"success":"email is sent successfully"},status=status.HTTP_200_OK)
    else:
        return Response({"error","not valid language "},status=status.HTTP_400_BAD_REQUEST)

def servererrorMessage(lang):
    if lang=='en': 
        return Response({"error":"Server Error try later"},status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    elif lang=='ar': 
        return Response({"error":"error ف السريفر حاول مرة اخري"},status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    elif lang=="":
       return Response({"error":"Server Error try later "},status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    else:
        return Response({"error","not valid language "},status=status.HTTP_400_BAD_REQUEST)
   
def passwordValidationError(lang):
    if lang=='en': 
        return Response({"error":" please enter new valid password"},status=status.HTTP_400_BAD_REQUEST)

    elif lang=='ar': 
        return Response({"error":" الرجاء ادخال كلمة مرور صالحة"},status=status.HTTP_400_BAD_REQUEST)
    elif lang=="":
       return Response({"error":" please enter new valid password"},status=status.HTTP_400_BAD_REQUEST)
    else:
        return Response({"error","not valid language "},status=status.HTTP_400_BAD_REQUEST)
    
def changePasswordSuccessfullyMessage(lang):
    if lang=='en': 
        return Response({"password changed successfully"},status=status.HTTP_200_OK)

    elif lang=='ar': 
        return Response({"تم تغيير كلمة المرور بنجاح"},status=status.HTTP_200_OK)
    elif lang=="":
       return Response({"password changed successfully"},status=status.HTTP_200_OK)
    else:
        return Response({"error","not valid language "},status=status.HTTP_400_BAD_REQUEST)