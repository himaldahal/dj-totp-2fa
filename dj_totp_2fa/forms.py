from django import forms
from django.utils.translation import gettext_lazy as _

from . import totp as core


class VerifyForm(forms.Form):
    code = forms.CharField(max_length=40, strip=True)
    method = forms.ChoiceField(choices=[("totp", "totp"), ("recovery", "recovery")], required=False)
    trust = forms.BooleanField(required=False)
    form_token = forms.CharField(required=False)

    def clean_code(self):
        return core.clean_code(self.cleaned_data["code"])


class ReauthForm(forms.Form):
    password = forms.CharField(required=False, max_length=256, strip=False)
    code = forms.CharField(required=False, max_length=40)

    def clean(self):
        data = super().clean()
        if not data.get("password") and not data.get("code"):
            raise forms.ValidationError(_("Enter your password or a current code."))
        if data.get("code"):
            data["code"] = core.clean_code(data["code"])
        return data


class DeviceNameForm(ReauthForm):
    name = forms.CharField(max_length=64, strip=True)


class DisableForm(ReauthForm):
    confirm = forms.BooleanField(required=True, error_messages={"required": _("Please tick the box to confirm.")})


class SetupConfirmForm(forms.Form):
    code = forms.CharField(max_length=20, strip=True)
    name = forms.CharField(max_length=64, required=False, strip=True)

    def clean_code(self):
        return core.clean_code(self.cleaned_data["code"])
