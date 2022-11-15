from .models import User
from django.db.models import Q

def authenticate( phoneOrEmailOrUsername=None, password=None, status=None):
    try:
        # search User model for email or phone for this user with incoming phoneOrEmail
        user = User.objects.get(Q(email=phoneOrEmailOrUsername) | Q(mobile=phoneOrEmailOrUsername)|Q(username=phoneOrEmailOrUsername))
        # check if existed password match incoming password
        passwordValid = user.check_password(password)
        # check if valid, then return user
        if passwordValid:
            if user.status ==status:            
                return user
        # else return None
            else:
                return None
    # check if eception of user not found in database occours, then handle it.
    except User.DoesNotExist:
        return None
