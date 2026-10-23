import time
from datetime import timedelta

from django.contrib.auth.models import Group
from django.contrib.messages import get_messages
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from dj_totp_2fa import session as sess
from dj_totp_2fa.models import TwoFactorProfile

from .base import TotpCase, code_for, enable, make_user, verified_client

VERIFY = reverse("dj_totp_2fa:verify")
SETUP = reverse("dj_totp_2fa:setup")


class EnforcementOnAnyLoginTests(TotpCase):
    """force_login imitates admin, allauth or a custom login view: they never touch our login view."""

    def test_unverified_html_request_is_redirected_to_verify(self):
        self.client.force_login(self.user)
        r = self.client.get("/private/")
        self.assertRedirects(r, VERIFY + "?next=/private/", fetch_redirect_response=False)

    def test_json_clients_get_401_with_machine_readable_code(self):
        self.client.force_login(self.user)
        for kwargs in ({"HTTP_ACCEPT": "application/json"}, {"HTTP_X_REQUESTED_WITH": "XMLHttpRequest"}):
            r = self.client.get("/private/", **kwargs)
            self.assertEqual(r.status_code, 401)
            body = r.json()
            self.assertEqual(body["code"], "two_factor_required")
            self.assertEqual(body["action"], "verify")
            self.assertFalse(body["ok"])
            self.assertIn("verify", body["url"])

    def test_api_prefix_always_json(self):
        self.client.force_login(self.user)
        r = self.client.get("/api/ping/")
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r["Content-Type"], "application/json")

    def test_json_post_content_type(self):
        self.client.force_login(self.user)
        r = self.client.post("/private/", data="{}", content_type="application/json")
        self.assertEqual(r.status_code, 401)

    def test_anonymous_requests_are_not_touched(self):
        r = Client().get("/private/")
        self.assertRedirects(r, "/account/2fa/login/?next=/private/", fetch_redirect_response=False)
        self.assertEqual(Client().get("/home/").status_code, 200)

    def test_verified_session_passes(self):
        client = verified_client(self.user, self.device)
        self.assertEqual(client.get("/private/").status_code, 200)

    def test_user_without_2fa_passes_when_not_required(self):
        other = make_user("nofa")
        client = Client()
        client.force_login(other)
        self.assertEqual(client.get("/private/").status_code, 200)

    def test_exempt_pages(self):
        self.client.force_login(self.user)
        for url in (reverse("dj_totp_2fa:verify"), reverse("dj_totp_2fa:setup"), reverse("dj_totp_2fa:login"), "/static/anything.css", "/admin/logout/"):
            r = self.client.get(url)
            self.assertNotEqual(r.get("Location", ""), VERIFY + "?next=" + url, url)

    def test_custom_exempt_urls(self):
        self.client.force_login(self.user)
        with override_settings(TOTP_EXEMPT_URLS=["private", r"^/home"]):
            self.assertEqual(self.client.get("/private/").status_code, 200)
        with override_settings(TOTP_EXEMPT_URLS=[r"^/priv"]):
            self.assertEqual(self.client.get("/private/").status_code, 200)
        with override_settings(TOTP_EXEMPT_URLS=["(unclosed"]):
            self.assertEqual(self.client.get("/private/").status_code, 302)

    def test_login_signal_clears_stale_verified_flags(self):
        client = verified_client(self.user, self.device)
        self.assertTrue(sess.VERIFIED_KEY in client.session)
        client.force_login(self.user)  # some other login view logs the same user in again
        self.assertNotIn(sess.VERIFIED_KEY, client.session)
        self.assertEqual(client.get("/private/").status_code, 302)

    def test_verified_flag_is_bound_to_the_user(self):
        client = verified_client(self.user, self.device)
        other = make_user("other")
        enable(other)
        session = client.session
        session["_auth_user_id"] = str(other.pk)  # swap identity under the same session
        session.save()
        self.assertEqual(client.get("/private/").status_code, 302)

    def test_helpers(self):
        client = verified_client(self.user, self.device)
        r = client.get(reverse("dj_totp_2fa:overview"))
        self.assertTrue(r.wsgi_request.is_two_factor_verified())
        self.assertTrue(r.wsgi_request.user.is_two_factor_verified())
        ctx = r.context["two_factor"]
        self.assertTrue(ctx.enabled and ctx.verified)
        self.assertEqual(ctx.devices.count(), 1)

    def test_verified_max_age_forces_reverification(self):
        client = verified_client(self.user, self.device)
        with override_settings(TOTP_VERIFIED_MAX_AGE=60):
            self.assertEqual(client.get("/private/").status_code, 200)
            session = client.session
            session[sess.VERIFIED_KEY] = time.time() - 120
            session.save()
            self.assertEqual(client.get("/private/").status_code, 302)


class PolicyTests(TestCase):
    def setUp(self):
        from django.core.cache import cache
        cache.clear()
        self.plain = make_user("plain")
        self.staff = make_user("staff", is_staff=True)
        self.root = make_user("root", is_staff=True, is_superuser=True)

    def reaches(self, user, url="/private/"):
        client = Client()
        client.force_login(user)
        return client.get(url)

    def test_default_is_not_required(self):
        self.assertEqual(self.reaches(self.plain).status_code, 200)

    def test_true_forces_enrolment(self):
        with override_settings(TOTP_REQUIRED=True):
            r = self.reaches(self.plain)
            self.assertRedirects(r, SETUP + "?next=/private/", fetch_redirect_response=False)

    def test_staff_and_superuser(self):
        with override_settings(TOTP_REQUIRED="staff"):
            self.assertEqual(self.reaches(self.plain).status_code, 200)
            self.assertEqual(self.reaches(self.staff).status_code, 302)
            self.assertEqual(self.reaches(self.root).status_code, 302)
        with override_settings(TOTP_REQUIRED="superuser"):
            self.assertEqual(self.reaches(self.staff).status_code, 200)
            self.assertEqual(self.reaches(self.root).status_code, 302)

    def test_group_names(self):
        group = Group.objects.create(name="finance")
        self.plain.groups.add(group)
        with override_settings(TOTP_REQUIRED=["finance", "ops"]):
            self.assertEqual(self.reaches(self.plain).status_code, 302)
            self.assertEqual(self.reaches(self.staff).status_code, 200)

    def test_callable_and_dotted_callable(self):
        with override_settings(TOTP_REQUIRED=lambda user, request: user.username == "plain"):
            self.assertEqual(self.reaches(self.plain).status_code, 302)
            self.assertEqual(self.reaches(self.staff).status_code, 200)
        with override_settings(TOTP_REQUIRED="dj_totp_2fa.tests.test_enforcement.only_staff"):
            self.assertEqual(self.reaches(self.plain).status_code, 200)
            self.assertEqual(self.reaches(self.staff).status_code, 302)

    def test_json_clients_get_403_for_enrolment(self):
        client = Client()
        client.force_login(self.plain)
        with override_settings(TOTP_REQUIRED=True):
            r = client.get("/api/ping/")
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.json()["action"], "enrol")

    def test_exempt_users_by_name_id_callable_and_profile(self):
        with override_settings(TOTP_REQUIRED=True, TOTP_EXEMPT_USERS=["plain"]):
            self.assertEqual(self.reaches(self.plain).status_code, 200)
            self.assertEqual(self.reaches(self.staff).status_code, 302)
        with override_settings(TOTP_REQUIRED=True, TOTP_EXEMPT_USERS=[self.staff.pk]):
            self.assertEqual(self.reaches(self.staff).status_code, 200)
        with override_settings(TOTP_REQUIRED=True, TOTP_EXEMPT_USERS=lambda u: u.is_superuser):
            self.assertEqual(self.reaches(self.root).status_code, 200)
        TwoFactorProfile.objects.create(user=self.plain, exempt=True)
        with override_settings(TOTP_REQUIRED=True):
            self.assertEqual(self.reaches(self.plain).status_code, 200)

    def test_enrolled_required_user_still_has_to_verify(self):
        enable(self.plain)
        with override_settings(TOTP_REQUIRED=True):
            self.assertEqual(self.reaches(self.plain).status_code, 302)

    def test_required_user_cannot_disable(self):
        client = verified_client(self.plain)
        with override_settings(TOTP_REQUIRED=True):
            r = client.post(reverse("dj_totp_2fa:disable"), {"password": "correct horse battery", "confirm": "1"})
            self.assertEqual(r.status_code, 403)
        self.assertTrue(self.plain.totp_devices.exists())


def only_staff(user, request):
    return user.is_staff


class GraceTests(TestCase):
    def setUp(self):
        from django.core.cache import cache
        cache.clear()
        self.user = make_user("graceful")
        self.client = Client()
        self.client.force_login(self.user)

    def test_grace_lets_user_in_then_forces_enrolment(self):
        with override_settings(TOTP_REQUIRED=True, TOTP_ENROLMENT_GRACE_DAYS=7):
            r = self.client.get("/private/")
            self.assertEqual(r.status_code, 200)
            profile = TwoFactorProfile.objects.get(user=self.user)
            self.assertAlmostEqual((profile.grace_until - timezone.now()).days, 6, delta=1)
            TwoFactorProfile.objects.update(grace_until=timezone.now() - timedelta(seconds=1))
            r = self.client.get("/private/")
            self.assertRedirects(r, SETUP + "?next=/private/", fetch_redirect_response=False)

    def test_deadline_does_not_restart(self):
        with override_settings(TOTP_REQUIRED=True, TOTP_ENROLMENT_GRACE_DAYS=7):
            self.client.get("/private/")
            first = TwoFactorProfile.objects.get().grace_until
            self.client.get("/private/")
            self.assertEqual(TwoFactorProfile.objects.get().grace_until, first)

    def test_reminder_message_is_shown_once_per_interval(self):
        with override_settings(TOTP_REQUIRED=True, TOTP_ENROLMENT_GRACE_DAYS=3):
            self.client.get("/private/")
            r = self.client.get("/private/")  # the second request must not queue a duplicate
            self.assertEqual(len(list(get_messages(r.wsgi_request))), 1)

    def test_banner_tag(self):
        from django.template import Context, Template
        with override_settings(TOTP_REQUIRED=True, TOTP_ENROLMENT_GRACE_DAYS=3):
            request = self.client.get("/private/").wsgi_request
            html = Template("{% load dj_totp_2fa %}{% totp_banner %}").render(Context({"request": request}))
        self.assertIn("totp-banner", html)
        self.assertIn(SETUP, html)

    def test_context_exposes_deadline(self):
        with override_settings(TOTP_REQUIRED=True, TOTP_ENROLMENT_GRACE_DAYS=3):
            r = self.client.get(reverse("dj_totp_2fa:overview"))
            self.assertIsNotNone(r.context["two_factor"].grace_until)
            self.assertTrue(r.context["two_factor"].required)

    def test_overview_page_shows_deadline(self):
        with override_settings(TOTP_REQUIRED=True, TOTP_ENROLMENT_GRACE_DAYS=3):
            r = self.client.get(reverse("dj_totp_2fa:overview"))
        self.assertContains(r, "Required by")

    def test_enrolment_ends_the_nagging(self):
        with override_settings(TOTP_REQUIRED=True, TOTP_ENROLMENT_GRACE_DAYS=3):
            self.client.get("/private/")
            enable(self.user)
            r = self.client.get("/private/")
            self.assertEqual(r.status_code, 302)  # now it must verify like everybody else


class DecoratorTests(TotpCase):
    def test_two_factor_required(self):
        self.assertRedirects(Client().get("/strict/"), "/account/2fa/login/?next=/strict/", fetch_redirect_response=False)
        self.client.force_login(self.user)
        self.assertRedirects(self.client.get("/strict/"), VERIFY + "?next=/strict/", fetch_redirect_response=False)
        client = verified_client(self.user, self.device)
        self.assertEqual(client.get("/strict/").status_code, 200)

    def test_two_factor_required_sends_unenrolled_users_to_setup(self):
        other = make_user("newbie")
        client = Client()
        client.force_login(other)
        self.assertRedirects(client.get("/strict/"), SETUP + "?next=/strict/", fetch_redirect_response=False)

    def test_otp_fresh_requires_recent_code(self):
        client = verified_client(self.user, self.device)
        self.assertEqual(client.get("/sensitive/").status_code, 200)  # just verified: fresh
        session = client.session
        session[sess.FRESH_KEY] = time.time() - 1000
        session.save()
        r = client.get("/sensitive/")
        self.assertRedirects(r, VERIFY + "?next=/sensitive/&fresh=1", fetch_redirect_response=False)
        r = client.get("/sensitive/", HTTP_ACCEPT="application/json")
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()["action"], "reverify")

    def test_step_up_flow_end_to_end(self):
        client = verified_client(self.user, self.device)
        session = client.session
        session[sess.FRESH_KEY] = time.time() - 1000
        session.save()
        page = client.get(VERIFY + "?next=/sensitive/&fresh=1")
        self.assertEqual(page.status_code, 200)
        self.assertContains(page, "Confirm it is you")
        r = client.post(VERIFY, {"code": code_for(self.device, 1)})
        self.assertRedirects(r, "/sensitive/", fetch_redirect_response=False)
        self.assertEqual(client.get("/sensitive/").status_code, 200)

    def test_otp_fresh_passes_for_users_without_2fa_unless_required(self):
        other = make_user("loner")
        client = Client()
        client.force_login(other)
        self.assertEqual(client.get("/sensitive/").status_code, 200)
        with override_settings(TOTP_REQUIRED=True):
            self.assertEqual(client.get("/sensitive/").status_code, 302)

    def test_reverify_setting_for_urls(self):
        client = verified_client(self.user, self.device)
        session = client.session
        session[sess.FRESH_KEY] = time.time() - 1000
        session.save()
        with override_settings(TOTP_REQUIRE_REVERIFY_FOR=[r"^/private/"], TOTP_REVERIFY_MAX_AGE=300):
            self.assertEqual(client.get("/private/").status_code, 302)
            self.assertEqual(client.get("/home/").status_code, 200)
        session = client.session
        session[sess.FRESH_KEY] = time.time()
        session.save()
        with override_settings(TOTP_REQUIRE_REVERIFY_FOR=["private"]):
            self.assertEqual(client.get("/private/").status_code, 200)

    def test_mixins(self):
        from django.http import HttpResponse
        from django.test import RequestFactory
        from django.views import View
        from dj_totp_2fa.decorators import OTPFreshMixin, TwoFactorRequiredMixin

        class Strict(TwoFactorRequiredMixin, View):
            def get(self, request):
                return HttpResponse("ok")

        class Fresh(OTPFreshMixin, View):
            otp_max_age = 10

            def get(self, request):
                return HttpResponse("ok")

        client = verified_client(self.user, self.device)
        request = RequestFactory().get("/x/")
        request.user = self.user
        request.session = client.session
        self.assertEqual(Strict.as_view()(request).status_code, 200)
        self.assertEqual(Fresh.as_view()(request).status_code, 200)
        session = client.session
        session[sess.FRESH_KEY] = time.time() - 100
        session.save()
        request.session = client.session
        self.assertEqual(Fresh.as_view()(request).status_code, 302)
        from django.contrib.auth.models import AnonymousUser
        request.user = AnonymousUser()
        self.assertEqual(Strict.as_view()(request).status_code, 302)

    def test_decorator_without_parentheses_and_with(self):
        from dj_totp_2fa.decorators import two_factor_required
        self.assertTrue(callable(two_factor_required(lambda r: None)))
        self.assertTrue(callable(two_factor_required()(lambda r: None)))
