from django import forms
from django.contrib.auth import password_validation
from . import models


class LoginForm(forms.Form):

    email = forms.EmailField(
        widget=forms.EmailInput(attrs={"placeholder": "Email", "class": "form-control"})
    )
    password = forms.CharField(
        widget=forms.PasswordInput(
            attrs={"placeholder": "Password", "class": "form-control"}
        )
    )

    def clean(self):
        email = self.cleaned_data.get("email")
        password = self.cleaned_data.get("password")
        try:
            user = models.User.objects.get(email=email)
            if user.check_password(password):
                return self.cleaned_data
            else:
                print("wrong")
                self.add_error("email", forms.ValidationError("잘못된 이메일 또는 비밀번호!입니다."))
        except models.User.DoesNotExist:
            self.add_error("email", forms.ValidationError("잘못된 이메일! 또는 비밀번호입니다."))


class SignUpForm(forms.ModelForm):
    class Meta:
        model = models.User
        fields = ("email",)

    email = forms.EmailField(
        widget=forms.EmailInput(attrs={"placeholder": "email", "class": "form-control"})
    )

    password = forms.CharField(
        widget=forms.PasswordInput(
            attrs={"placeholder": "비밀번호", "class": "form-control"}
        )
    )
    password1 = forms.CharField(
        label="Confirm Password",
        widget=forms.PasswordInput(
            attrs={"placeholder": "비밀번호 확인", "class": "form-control"}
        ),
    )

    def clean_email(self):
        email = self.cleaned_data.get("email")
        try:
            models.User.objects.get(email=email)
            raise forms.ValidationError(
                "That email is already taken", code="existing_user"
            )
        except models.User.DoesNotExist:
            return email

    def clean_password1(self):
        password = self.cleaned_data.get("password")
        password1 = self.cleaned_data.get("password1")
        if password != password1:
            raise forms.ValidationError("비밀번호가 다릅니다.")
        else:
            if password_validation.validate_password(password, password1) is not None:
                raise forms.ValidationError("invalid password")
            return password

    def save(self, *args, **kwargs):
        user = super().save(commit=False)
        email = self.cleaned_data.get("email")
        password = self.cleaned_data.get("password")
        user.username = email
        user.set_password(password)
        user.save()
