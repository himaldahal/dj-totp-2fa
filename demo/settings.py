"""A tiny project that shows dj-totp-2fa working. Not for production (DEBUG on, fixed secret key)."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DEBUG = True
SECRET_KEY = "demo-only-secret-key-do-not-use-anywhere-else"
ALLOWED_HOSTS = ["*"]
ROOT_URLCONF = "demo.urls"
INSTALLED_APPS = [
    "django.contrib.admin", "django.contrib.auth", "django.contrib.contenttypes", "django.contrib.sessions",
    "django.contrib.messages", "django.contrib.staticfiles", "dj_totp_2fa",
]
MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware", "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware", "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware", "dj_totp_2fa.middleware.TwoFactorMiddleware",
]
TEMPLATES = [{
    "BACKEND": "django.template.backends.django.DjangoTemplates", "DIRS": [BASE_DIR / "templates"], "APP_DIRS": True,
    "OPTIONS": {"context_processors": [
        "django.template.context_processors.request", "django.contrib.auth.context_processors.auth",
        "django.contrib.messages.context_processors.messages", "dj_totp_2fa.context_processors.two_factor"]},
}]
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": os.environ.get("DEMO_DB", str(BASE_DIR / "db.sqlite3"))}}
CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
STATIC_URL = "/static/"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
USE_TZ = True
TIME_ZONE = "UTC"
EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"
LOGIN_URL = "dj_totp_2fa:login"
LOGIN_REDIRECT_URL = "/"

# dj-totp-2fa
TOTP_THEME = os.environ.get("TOTP_THEME", "clean")
TOTP_ISSUER = "Acme Cloud"
TOTP_BRAND_NAME = "Acme Cloud"
TOTP_MIN_SUBMIT_SECONDS = 0
TOTP_REQUIRED = lambda user, request: user.get_username() == "forced"  # noqa: E731  (demo of a callable policy)
TOTP_ENDPOINT_RATE_LIMITS = {"verify": (1000, 60), "setup": (1000, 60), "recovery": (1000, 60), "api": (1000, 60), "reauth": (1000, 60)}
SHOTS = os.environ.get("DEMO_SHOTS") == "1"  # enables the /_shot/ helper views used by scripts/capture_screenshots.py
