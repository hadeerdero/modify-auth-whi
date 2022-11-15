from django.contrib import admin
from .models import (User)


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = (
        "genderChoices",
        "id",
        "email",
        "gender",
        "fullname",
        "dob",
        "mobile",
        "country",
        "isEmailVerified",
        "isPhoneVerified",
        "is_active",
        "is_staff",
        "status",
        "verificationcode",
        "createdAt",
        "updatedAt"
    )
