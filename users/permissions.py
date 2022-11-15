from rest_framework import permissions
import uuid

class IsVerified(permissions.BasePermission):
    message = {
        "not_email_phone_verified":"phone number or email are not verified"
    }
    def has_permission(self, request, view):
        try : 
            if  request.user.isEmailVerified and request.user.isPhoneVerified:
                return True 
            else :
                return False 
        except  :
            return False
