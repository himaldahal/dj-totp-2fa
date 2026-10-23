import csv
import io

from django.contrib import admin
from django.contrib.admin import AdminSite
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import Permission
from django.test import Client, RequestFactory, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from dj_totp_2fa import api, ratelimit
from dj_totp_2fa.admin import TwoFactorStatusFilter, TwoFactorUserAdminMixin
from dj_totp_2fa.adminlogin import OTPAdminSite
from dj_totp_2fa.models import Lockout, RecoveryCode, TOTPDevice, TrustedBrowser, TwoFactorEvent

from .base import PASSWORD, code_for, enable, login, make_user, verified_client

NO_MIDDLEWARE = [m for m in __import__("django.conf", fromlist=["settings"]).settings.MIDDLEWARE if "dj_totp_2fa" not in m]


class AdminLoginProtectionTests(TestCase):
    def setUp(self):
        from django.core.cache import cache
        cache.clear()
        self.staff = make_user("boss", is_staff=True, is_superuser=True)

    def admin_login(self, client, **extra):
        return client.post("/admin/login/", dict({"username": self.staff.username, "password": PASSWORD, "next": "/admin/"}, **extra))

    def test_admin_login_requires_the_code_when_enabled(self):
        device = enable(self.staff)
        client = Client()
        r = self.admin_login(client)
        self.assertRedirects(r, reverse("dj_totp_2fa:verify"), fetch_redirect_response=False)
        self.assertNotIn("_auth_user_id", client.session)
        self.assertEqual(client.get("/admin/").status_code, 302)
        r = client.post(reverse("dj_totp_2fa:verify"), {"code": code_for(device)})
        self.assertRedirects(r, "/admin/", fetch_redirect_response=False)
        self.assertEqual(client.get("/admin/").status_code, 200)

    def test_admin_login_page_still_renders_with_admin_template(self):
        r = Client().get("/admin/login/")
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "id_username")

    def test_staff_without_2fa_logs_in_normally_unless_required(self):
        client = Client()
        r = self.admin_login(client)
        self.assertRedirects(r, "/admin/", fetch_redirect_response=False)
        self.assertEqual(client.get("/admin/").status_code, 200)

    def test_required_for_staff_forces_enrolment_in_admin(self):
        client = Client()
        with override_settings(TOTP_REQUIRED="staff"):
            self.admin_login(client)
            r = client.get("/admin/")
        self.assertRedirects(r, reverse("dj_totp_2fa:setup") + "?next=/admin/", fetch_redirect_response=False)

    def test_wrong_password_in_admin(self):
        r = self.admin_login(Client(), password="nope")
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "Please enter the correct")

    def test_protection_without_the_middleware(self):
        enable(self.staff)
        client = Client()
        with override_settings(MIDDLEWARE=NO_MIDDLEWARE):
            client.force_login(self.staff)  # e.g. some SSO login
            r = client.get("/admin/")
            self.assertEqual(r.status_code, 302)
            self.assertIn("/admin/login/", r["Location"])
            r = client.get("/admin/login/?next=/admin/")
            self.assertEqual(r.status_code, 302)
            self.assertIn("/verify/", r["Location"])

    def test_protect_admin_off_leaves_admin_login_alone(self):
        enable(self.staff)
        client = Client()
        with override_settings(TOTP_PROTECT_ADMIN=False, MIDDLEWARE=NO_MIDDLEWARE):
            r = self.admin_login(client)
            self.assertRedirects(r, "/admin/", fetch_redirect_response=False)
            self.assertEqual(client.get("/admin/").status_code, 200)

    def test_otp_admin_site_is_strict(self):
        site = OTPAdminSite(name="strict")
        request = RequestFactory().get("/")
        request.user = self.staff
        request.session = Client().session
        self.assertFalse(site.has_permission(request))  # no 2FA at all -> not enough
        self.assertTrue(AdminSite().has_permission(request))
        from dj_totp_2fa import session as sess
        sess.mark_verified(request, self.staff, "totp")
        self.assertTrue(site.has_permission(request))


class AdminPagesTests(TestCase):
    def setUp(self):
        from django.core.cache import cache
        cache.clear()
        self.root = make_user("root", is_staff=True, is_superuser=True)
        self.device = enable(self.root)
        self.user = make_user("victim")
        self.victim_device = enable(self.user)
        self.codes = api.generate_recovery_codes(self.user)
        self.client = verified_client(self.root, self.device)

    def test_all_changelists_render(self):
        TwoFactorEvent.objects.create(event="verified", identifier="x")
        for model in ("totpdevice", "recoverycode", "trustedbrowser", "twofactorevent", "lockout", "twofactorprofile"):
            r = self.client.get(reverse("admin:dj_totp_2fa_%s_changelist" % model))
            self.assertEqual(r.status_code, 200, model)

    def test_device_page_shows_nothing_secret(self):
        r = self.client.get(reverse("admin:dj_totp_2fa_totpdevice_change", args=[self.victim_device.pk]))
        self.assertEqual(r.status_code, 200)
        body = r.content.decode()
        self.assertNotIn(self.victim_device.secret, body)
        self.assertNotIn(self.victim_device.secret_encrypted, body)
        self.assertNotIn("secret_encrypted", body)

    def test_recovery_code_admin_shows_no_hash(self):
        row = RecoveryCode.objects.filter(user=self.user).first()
        r = self.client.get(reverse("admin:dj_totp_2fa_recoverycode_change", args=[row.pk]))
        self.assertNotContains(r, row.code_hash)
        r = self.client.get(reverse("admin:dj_totp_2fa_recoverycode_changelist"))
        self.assertNotContains(r, row.code_hash)

    def test_events_are_read_only_and_exportable(self):
        e = TwoFactorEvent.objects.create(event="verified", identifier="alice", details={"a": 1})
        self.assertEqual(self.client.get(reverse("admin:dj_totp_2fa_twofactorevent_add")).status_code, 403)
        r = self.client.post(reverse("admin:dj_totp_2fa_twofactorevent_change", args=[e.pk]), {"event": "tampered"})
        self.assertEqual(r.status_code, 403)
        e.refresh_from_db()
        self.assertEqual(e.event, "verified")
        r = self.client.post(reverse("admin:dj_totp_2fa_twofactorevent_changelist"), {"action": "export_csv", "_selected_action": [e.pk]})
        self.assertEqual(r["Content-Type"], "text/csv")
        rows = list(csv.reader(io.StringIO(r.content.decode())))
        self.assertEqual(rows[0][:2], ["time", "event"])
        self.assertEqual(rows[1][1], "verified")

    def test_event_model_is_append_only(self):
        e = TwoFactorEvent.objects.create(event="x")
        e.event = "y"
        with self.assertRaises(PermissionError):
            e.save()

    def test_event_filters_and_search(self):
        TwoFactorEvent.objects.create(event="lockout", identifier="mallory")
        r = self.client.get(reverse("admin:dj_totp_2fa_twofactorevent_changelist") + "?q=mallory&event=lockout")
        self.assertContains(r, "mallory")

    def test_reset_action_audited_and_notifies(self):
        from django.core import mail
        r = self.client.post(reverse("admin:dj_totp_2fa_totpdevice_changelist"),
                             {"action": "reset_users", "_selected_action": [self.victim_device.pk]})
        self.assertEqual(r.status_code, 302)
        self.assertFalse(api.is_enabled(self.user))
        self.assertEqual(RecoveryCode.objects.filter(user=self.user).count(), 0)
        event = TwoFactorEvent.objects.get(event="admin_reset")
        self.assertEqual(event.user, self.user)
        self.assertEqual(event.details["actor"], self.root.pk)
        self.assertTrue(any("turned off" in m.subject for m in mail.outbox))

    def test_reset_needs_permission(self):
        staff = make_user("helper", is_staff=True)
        staff.user_permissions.add(*Permission.objects.filter(content_type__app_label="dj_totp_2fa", codename__in=("view_totpdevice", "change_totpdevice")))
        enable(staff)
        client = verified_client(staff)
        client.post(reverse("admin:dj_totp_2fa_totpdevice_changelist"), {"action": "reset_users", "_selected_action": [self.victim_device.pk]})
        self.assertTrue(api.is_enabled(self.user))
        staff.user_permissions.add(Permission.objects.get(codename="reset_two_factor"))
        client = verified_client(User_refresh(staff), offset=1)
        client.post(reverse("admin:dj_totp_2fa_totpdevice_changelist"), {"action": "reset_users", "_selected_action": [self.victim_device.pk]})
        self.assertFalse(api.is_enabled(self.user))

    def test_disable_and_enable_actions(self):
        url = reverse("admin:dj_totp_2fa_totpdevice_changelist")
        self.client.post(url, {"action": "disable_devices", "_selected_action": [self.victim_device.pk]})
        self.victim_device.refresh_from_db()
        self.assertFalse(self.victim_device.confirmed)
        self.client.post(url, {"action": "enable_devices", "_selected_action": [self.victim_device.pk]})
        self.victim_device.refresh_from_db()
        self.assertTrue(self.victim_device.confirmed)
        fresh = api.create_device(self.user, "never confirmed")
        self.client.post(url, {"action": "enable_devices", "_selected_action": [fresh.pk]})
        fresh.refresh_from_db()
        self.assertFalse(fresh.confirmed)  # cannot be switched on without proof of possession

    def test_trusted_browser_revoke_action(self):
        row = TrustedBrowser.objects.create(user=self.user, token_hash="a" * 64, expires_at=timezone.now() + timezone.timedelta(days=1))
        self.client.post(reverse("admin:dj_totp_2fa_trustedbrowser_changelist"), {"action": "revoke", "_selected_action": [row.pk]})
        self.assertFalse(TrustedBrowser.objects.exists())
        self.assertTrue(TwoFactorEvent.objects.filter(event="trusted_revoked").exists())

    def test_lockout_clear_action(self):
        from .test_ratelimit import fail
        fail(self.user, n=10)
        row = Lockout.objects.get(scope="user")
        self.client.post(reverse("admin:dj_totp_2fa_lockout_changelist"), {"action": "clear", "_selected_action": [row.pk]})
        self.assertFalse(Lockout.objects.exists())
        self.assertTrue(api.verify_code(self.user, code_for(self.victim_device)).ok)


def User_refresh(user):
    return type(user).objects.get(pk=user.pk)


class UserAdminMixinTests(TestCase):
    def setUp(self):
        from django.core.cache import cache
        cache.clear()
        self.site = AdminSite(name="mixin")

        class Mixed(TwoFactorUserAdminMixin, UserAdmin):
            pass

        from django.contrib.auth import get_user_model
        self.model_admin = Mixed(get_user_model(), self.site)
        self.root = make_user("root", is_staff=True, is_superuser=True)
        self.with_2fa = make_user("secure")
        enable(self.with_2fa)
        self.without = make_user("plain")

    def request(self):
        request = RequestFactory().get("/")
        request.user = self.root
        return request

    def test_column(self):
        self.assertIn("two_factor_status", self.model_admin.get_list_display(self.request()))
        self.assertTrue(self.model_admin.two_factor_status(self.with_2fa))
        self.assertFalse(self.model_admin.two_factor_status(self.without))

    def test_filter(self):
        self.assertIn(TwoFactorStatusFilter, self.model_admin.get_list_filter(self.request()))
        from django.contrib.auth import get_user_model
        qs = get_user_model().objects.all()
        f = TwoFactorStatusFilter(self.request(), {"two_factor": ["on"]}, get_user_model(), self.model_admin)
        self.assertEqual(list(f.queryset(self.request(), qs)), [self.with_2fa])
        f = TwoFactorStatusFilter(self.request(), {"two_factor": ["off"]}, get_user_model(), self.model_admin)
        self.assertNotIn(self.with_2fa, f.queryset(self.request(), qs))

    def test_action_is_listed_for_privileged_users_and_resets(self):
        actions = self.model_admin.get_actions(self.request())
        self.assertIn("reset_two_factor", actions)
        from django.contrib.messages.storage.fallback import FallbackStorage
        request = self.request()
        request.session = {}
        request._messages = FallbackStorage(request)
        from django.contrib.auth import get_user_model
        self.model_admin.reset_two_factor(request, get_user_model().objects.filter(pk=self.with_2fa.pk))
        self.assertFalse(api.is_enabled(self.with_2fa))

    def test_action_hidden_without_permission(self):
        request = self.request()
        request.user = self.without
        self.assertNotIn("reset_two_factor", self.model_admin.get_actions(request))
