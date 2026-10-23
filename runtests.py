#!/usr/bin/env python
"""Standalone test runner: ``python runtests.py [test labels]`` (needs only Django)."""
import sys

import django
from django.conf import settings
from django.contrib import admin
from django.urls import include, path

settings.configure(
    DEBUG=False, SECRET_KEY="test-only-secret-key", ALLOWED_HOSTS=["*"], ROOT_URLCONF=__name__, USE_TZ=True,
    TIME_ZONE="Asia/Kathmandu", DEFAULT_AUTO_FIELD="django.db.models.BigAutoField",
    DATABASES={"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}},
    INSTALLED_APPS=["django.contrib.admin", "django.contrib.auth", "django.contrib.contenttypes",
                    "django.contrib.sessions", "django.contrib.messages", "dj_totp_2fa"],
    MIDDLEWARE=["django.contrib.sessions.middleware.SessionMiddleware", "django.middleware.common.CommonMiddleware",
                "django.middleware.csrf.CsrfViewMiddleware", "django.contrib.auth.middleware.AuthenticationMiddleware",
                "django.contrib.messages.middleware.MessageMiddleware", "dj_totp_2fa.middleware.TwoFactorMiddleware"],
    TEMPLATES=[{"BACKEND": "django.template.backends.django.DjangoTemplates", "APP_DIRS": True, "OPTIONS": {
        "context_processors": ["django.template.context_processors.request",
                               "django.contrib.auth.context_processors.auth",
                               "django.contrib.messages.context_processors.messages",
                               "dj_totp_2fa.context_processors.two_factor"]}}],
    PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"],
    STATIC_URL="/static/", LOGIN_URL="/account/2fa/login/", LOGIN_REDIRECT_URL="/home/",
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "totp-tests"}},
    TOTP_MIN_SUBMIT_SECONDS=0,
)
django.setup()

from django.http import HttpResponse  # noqa: E402
from django.contrib.auth.decorators import login_required  # noqa: E402
from dj_totp_2fa.decorators import otp_fresh, two_factor_required  # noqa: E402


def home(request):
    return HttpResponse("home")


@login_required
def private(request):
    return HttpResponse("private")


@two_factor_required
def strict(request):
    return HttpResponse("strict")


@otp_fresh(max_age=300)
def sensitive(request):
    return HttpResponse("sensitive")


def api_ping(request):
    return HttpResponse("{}", content_type="application/json") if request.user.is_authenticated else HttpResponse(status=401)


urlpatterns = [
    path("admin/", admin.site.urls),
    path("account/2fa/", include("dj_totp_2fa.urls")),
    path("home/", home, name="home"),
    path("private/", private, name="private"),
    path("strict/", strict, name="strict"),
    path("sensitive/", sensitive, name="sensitive"),
    path("api/ping/", api_ping, name="api_ping"),
]

if __name__ == "__main__":
    import contextlib
    import io

    from django.test.runner import DiscoverRunner

    class QuietRunner(DiscoverRunner):
        """Keeps unittest's summary out of the way on success; shows everything on failure."""

        def get_test_runner_kwargs(self):
            kwargs = super().get_test_runner_kwargs()
            kwargs["stream"] = self.buffer = io.StringIO()
            return kwargs

    labels = sys.argv[1:] or ["dj_totp_2fa"]
    runner = QuietRunner(verbosity=0, interactive=False)
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        failures = runner.run_tests(labels)
    if failures:
        sys.stderr.write(out.getvalue() + getattr(runner, "buffer", io.StringIO()).getvalue())
    print("All tests passed." if not failures else f"{failures} test(s) failed.")
    sys.exit(bool(failures))
