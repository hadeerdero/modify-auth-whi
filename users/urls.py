# import path, include from django
from django.urls import path, include
# imports from restframework for token
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
# import necessary methods from views
from .views import (login,register, verifyEmail,resendEmailVerfication,checkEmailIfExist,checkPhoneIfExist,passwordRestVerificationByEmail,
                    passwordResetByTokens,passwordRestVerificationByPhone,SendverifyPhoneCode,verifyPhone,findUser,passwordResetByPhoneCodeCheck,
                    passwordResetByPhone,checkUserEmailVerified,checkUserPhoneVerified,singUpStep1,passwordRestVerificationByEmailOrMobile,changePassword)


urlpatterns = [
    # login url
    path("login", login, name="login"),
    # register url
    path("register",register,name="register"),
    # verify-email url
    path("verify-email",verifyEmail,name="verifyEmail"),
    # resend-verify-email url
    path("resend-verify-email",resendEmailVerfication,name="resendEmailVerfication"),
    # send-verify-phone url
    path("send-verify-phone",SendverifyPhoneCode,name="verifyPhone"),
    # verify-phone url
    path("verify-phone",verifyPhone,name="verifyPhone"),
    # find-user url
    path("find-user",findUser,name="findUser"),
    # reset-password-verification-email url
    path("reset-password-verification-email",passwordRestVerificationByEmail,name="passwordRestVerification"),
    # reset-password-verification-phone url
    path("reset-password-verification-phone",passwordRestVerificationByPhone,name="passwordRestVerificationByPhone"),
    # reset-password-by-email url
    path("reset-password-by-email",passwordResetByTokens,name="passwordResetByTokens"),
    # reset-password-by-phone-check url
    path("reset-password-by-phone-check",passwordResetByPhoneCodeCheck,name="passwordResetByPhoneCodeCheck"),
    # reset-password-by-phone url
    path("reset-password-by-phone",passwordResetByPhone,name="passwordResetByPhone"),
    # check-email-exist url
    path("check-email-exist",checkEmailIfExist,name="checkEmailIfExist"),
    # check-phone-exist url
    path("check-phone-exist",checkPhoneIfExist,name="checkPhoneIfExist"),
    # check-email-verified url
    path("check-email-verified",checkUserEmailVerified,name="checkUserEmailVerified"),
    # check-phone-verified url
    path("check-phone-verified",checkUserPhoneVerified,name="checkUserPhoneVerified"),
    # token_obtain_pair url
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    # token_refresh url
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    ######### new urls by hadeer
    path("sign-up-step1",singUpStep1,name="singUpStep1"),
    path("password-Rest-Verification-ByEmailOrMobile",passwordRestVerificationByEmailOrMobile,name="passwordRestVerificationByEmailOrMobile"),
    path("changePassword",changePassword,name="passwordRestVerificationByEmailOrMobile")



    
]