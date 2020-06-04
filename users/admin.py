from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from . import models


@admin.register(models.User)
class CustomUserAdmin(UserAdmin):

    fieldsets = UserAdmin.fieldsets + (
        (
            "custom fields",
            {"fields": ("email_verified", "email_secret", "login_method",)},
        ),
    )

    list_display = (
        "username",
        "email",
        "email_verified",
        "login_method",
    )
