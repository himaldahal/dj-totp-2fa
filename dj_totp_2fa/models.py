from datetime import timedelta

from django.conf import settings
from django.db import models, transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from . import crypto, totp as totp_core

ALGORITHM_CHOICES = [("SHA1", "SHA1"), ("SHA256", "SHA256"), ("SHA512", "SHA512")]


class TOTPDevice(models.Model):
    """An authenticator app registered by a user. The secret is stored encrypted when configured (see crypto.py)."""

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="totp_devices")
    name = models.CharField(_("name"), max_length=64, default="Authenticator")
    secret_encrypted = models.TextField(_("secret (stored form)"), editable=False)
    algorithm = models.CharField(max_length=8, choices=ALGORITHM_CHOICES, default="SHA1")
    digits = models.PositiveSmallIntegerField(default=6)
    period = models.PositiveSmallIntegerField(default=30)
    window = models.PositiveSmallIntegerField(null=True, blank=True, help_text=_("Steps either side accepted; empty uses the global setting."))
    drift_steps = models.SmallIntegerField(default=0, help_text=_("Stored clock offset in steps (only with drift resync)."))
    confirmed = models.BooleanField(default=False)
    primary = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    confirmed_at = models.DateTimeField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    last_used_step = models.BigIntegerField(default=0, help_text=_("Replay protection: codes for this step or earlier are refused."))
    failure_count = models.PositiveIntegerField(default=0)

    class Meta:
        verbose_name = _("TOTP device")
        verbose_name_plural = _("TOTP devices")
        ordering = ["-primary", "created_at", "pk"]
        constraints = [models.UniqueConstraint(fields=["user", "name"], name="dj_totp_2fa_unique_device_name")]
        permissions = [("reset_two_factor", "Can reset two-factor authentication for users")]

    def __str__(self):
        return "%s (%s)" % (self.name, "confirmed" if self.confirmed else "pending")

    def __repr__(self):
        return "<TOTPDevice id=%s user_id=%s name=%r confirmed=%s>" % (self.pk, self.user_id, self.name, self.confirmed)

    @property
    def secret(self):
        """The base32 secret. Treat it as sensitive; it is never logged or shown by the admin."""
        return crypto.decrypt(self.secret_encrypted)

    @secret.setter
    def secret(self, base32):
        self.secret_encrypted = crypto.encrypt(base32)

    @property
    def secret_bytes(self):
        return totp_core.b32decode(self.secret)

    def save(self, *args, **kwargs):
        with transaction.atomic():
            super().save(*args, **kwargs)
            if self.primary:
                type(self).objects.filter(user_id=self.user_id, primary=True).exclude(pk=self.pk).update(primary=False)

    def uri(self, request=None):
        from .api import build_uri
        return build_uri(self, request)


class RecoveryCode(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="totp_recovery_codes")
    code_hash = models.CharField(max_length=255, editable=False)
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    used_at = models.DateTimeField(null=True, blank=True)
    used_ip = models.GenericIPAddressField(null=True, blank=True)

    class Meta:
        verbose_name = _("recovery code")
        verbose_name_plural = _("recovery codes")
        ordering = ["pk"]

    def __str__(self):
        return "Recovery code #%s (%s)" % (self.pk, "used" if self.used_at else "unused")

    def __repr__(self):
        return "<RecoveryCode id=%s user_id=%s used=%s>" % (self.pk, self.user_id, bool(self.used_at))


class TrustedBrowser(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="totp_trusted_browsers")
    token_hash = models.CharField(max_length=64, unique=True, editable=False)
    label = models.CharField(max_length=120, blank=True)
    user_agent_summary = models.CharField(max_length=160, blank=True)
    ip = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    expires_at = models.DateTimeField()
    last_seen_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = _("trusted browser")
        verbose_name_plural = _("trusted browsers")
        ordering = ["-created_at"]

    def __str__(self):
        return self.label or "Trusted browser #%s" % self.pk

    def __repr__(self):
        return "<TrustedBrowser id=%s user_id=%s>" % (self.pk, self.user_id)

    @property
    def is_active(self):
        return self.expires_at > timezone.now()


class TwoFactorEvent(models.Model):
    """Append-only audit trail. Rows cannot be edited after creation; they are removed by retention or user deletion."""

    user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.CASCADE, related_name="+")
    identifier = models.CharField(max_length=150, blank=True, help_text=_("Username at the time of the event."))
    event = models.CharField(max_length=40, db_index=True)
    ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=255, blank=True)
    details = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(default=timezone.now, db_index=True, editable=False)

    class Meta:
        verbose_name = _("two-factor event")
        verbose_name_plural = _("two-factor events")
        ordering = ["-created_at", "-pk"]

    def __str__(self):
        return "%s @ %s" % (self.event, self.created_at)

    def save(self, *args, **kwargs):
        if self.pk and not self._state.adding:
            raise PermissionError("TwoFactorEvent rows are append-only.")
        super().save(*args, **kwargs)


class Lockout(models.Model):
    SCOPE_USER, SCOPE_IP, SCOPE_PENDING = "user", "ip", "pending"
    SCOPES = [(SCOPE_USER, "user"), (SCOPE_IP, "ip"), (SCOPE_PENDING, "pending")]

    scope = models.CharField(max_length=10, choices=SCOPES)
    key_hash = models.CharField(max_length=64, help_text=_("HMAC of the user id, IP group or pending login. Never the raw value."))
    user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.CASCADE, related_name="+")
    until = models.DateTimeField()
    reason = models.CharField(max_length=120, blank=True)
    level = models.PositiveSmallIntegerField(default=0)
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    updated_at = models.DateTimeField(default=timezone.now)

    class Meta:
        verbose_name = _("lockout")
        verbose_name_plural = _("lockouts")
        ordering = ["-until"]
        constraints = [models.UniqueConstraint(fields=["scope", "key_hash"], name="dj_totp_2fa_unique_lockout")]

    def __str__(self):
        return "%s lockout until %s" % (self.scope, self.until)

    @property
    def active(self):
        return self.until > timezone.now()


class TwoFactorProfile(models.Model):
    """Per-user state: enrolment grace period and an administrator controlled exemption."""

    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="totp_profile")
    grace_started_at = models.DateTimeField(null=True, blank=True)
    grace_until = models.DateTimeField(null=True, blank=True)
    exempt = models.BooleanField(default=False, help_text=_("Never require 2FA for this user."))
    last_nag_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = _("two-factor profile")
        verbose_name_plural = _("two-factor profiles")

    def __str__(self):
        return "2FA profile of user %s" % self.user_id

    def grace_active(self):
        return bool(self.grace_until and self.grace_until > timezone.now())


def grace_deadline(days, start=None):
    return (start or timezone.now()) + timedelta(days=days)
