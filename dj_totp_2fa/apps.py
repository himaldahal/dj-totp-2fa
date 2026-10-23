from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class TwoFactorConfig(AppConfig):
    name = "dj_totp_2fa"
    label = "dj_totp_2fa"
    verbose_name = _("Two-factor authentication")
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self):
        from . import checks, receivers  # noqa: F401
        from .adminlogin import install

        install()
