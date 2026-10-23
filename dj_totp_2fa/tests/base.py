import time

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import Client, TestCase, TransactionTestCase, override_settings
from django.urls import reverse

from dj_totp_2fa import api, totp as core
from dj_totp_2fa.models import TOTPDevice

User = get_user_model()
PASSWORD = "correct horse battery"


def make_user(name="alice", **extra):
    if User.USERNAME_FIELD == "username":
        return User.objects.create_user(name, "%s@example.com" % name, PASSWORD, **extra)
    return User.objects.create_user(email="%s@example.com" % name, password=PASSWORD, **extra)


def enable(user, name="Phone", **params):
    """Give ``user`` a confirmed device and return it."""
    device = api.create_device(user, name, **params)
    TOTPDevice.objects.filter(pk=device.pk).update(confirmed=True, primary=True, confirmed_at=device.created_at)
    device.refresh_from_db()
    return device


def code_for(device, offset=0):
    return core.hotp(device.secret_bytes, core.time_step(None, device.period) + offset, device.digits, device.algorithm)


def next_code(device):
    """A valid code for the next step (not yet used), handy after a code was consumed."""
    return code_for(device, 1)


def login(client, user, password=PASSWORD, **extra):
    return client.post(reverse("dj_totp_2fa:login"), dict({"username": user.get_username(), "password": password}, **extra))


def verified_client(user, device=None, offset=0):
    """A Client whose session is fully verified (password + code). Use offset=1 when the current code was consumed."""
    device = device or user.totp_devices.filter(confirmed=True).first() or enable(user)
    client = Client()
    login(client, user)
    client.post(reverse("dj_totp_2fa:verify"), {"code": code_for(device, offset)})
    return client


class FlowMixin:
    def setUp(self):
        super().setUp()
        cache.clear()
        self.user = make_user()
        self.device = enable(self.user)
        self.client = Client()


class TotpCase(FlowMixin, TestCase):
    pass


class TotpTransactionCase(FlowMixin, TransactionTestCase):
    pass
