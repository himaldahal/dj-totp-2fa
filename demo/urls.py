from django.conf import settings
from django.contrib import admin
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.urls import include, path

from dj_totp_2fa.decorators import otp_fresh


@login_required
def home(request):
    return render(request, "demo/home.html")


@otp_fresh(max_age=120)
def sensitive(request):
    return render(request, "demo/sensitive.html")


urlpatterns = [
    path("", home, name="home"),
    path("billing/", sensitive, name="billing"),
    path("admin/", admin.site.urls),
    path("account/2fa/", include("dj_totp_2fa.urls")),
]
if settings.SHOTS:
    from . import shots

    urlpatterns.append(path("_shot/<str:scenario>/", shots.shot))
